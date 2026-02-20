# Reverse-Engineering KakaoTalk's LOCO Protocol in Go

A chronicle of building `amso`, a from-scratch Go implementation of KakaoTalk's binary LOCO protocol. What started as a straightforward port of [node-kakao](https://github.com/storycraft/node-kakao) turned into a multi-day rabbit hole of decompiling APKs, hex-dumping encrypted payloads, and automating an Android emulator to tap through verification dialogs.

**3,718 lines of Go across 22 files. 6 layers of protocol. 5 show-stopping bugs.**

---

## The Goal

[KakaoTalk](https://www.kakaocorp.com/page/service/service/KakaoTalk) is South Korea's dominant messaging app -- ~53 million monthly active users, 97% market penetration. Unlike WhatsApp or Signal, KakaoTalk doesn't use a standard messaging protocol. It uses a proprietary binary protocol called **LOCO** that pushes [BSON](https://bsonspec.org/) (Binary JSON, the format MongoDB uses) payloads over raw TCP sockets.

There is no public API. There is no documentation. The only way to build a third-party client is to reverse-engineer the wire format.

The goal: build a Go SDK that speaks LOCO natively. It will eventually back a [mautrix-go](https://github.com/mautrix/go) bridge so KakaoTalk conversations can be mirrored into [Matrix](https://matrix.org/), an open federated messaging protocol. But step one is just getting a `LOGINLIST` response from a live KakaoTalk server.

Our starting point is [node-kakao](https://github.com/storycraft/node-kakao), a community TypeScript implementation of the LOCO protocol. The plan: read its source, understand the protocol, rewrite in Go. Simple enough.

The connection flow looks simple on paper:

```
HTTP login.json  -->  access_token
                         |
              booking (GETCONF over TLS)
                         |
              checkin (CHECKIN over encrypted TCP)
                         |
              main server (LOGINLIST over encrypted TCP)
                         |
                    channels, messages, push events
```

Four hops before you can send a message. Each hop uses a different transport. The booking step fetches server configuration (like a DNS-over-LOCO lookup). Checkin tells you which main server to connect to based on your user ID and geography. Only after LOGINLIST succeeds on the main server do you have a persistent session that receives push events.

It was not simple.

## The Wire Format

LOCO packets have a 22-byte header followed by a BSON body:

```
Offset  Size   Field
0       4      Packet ID (uint32 LE)
4       2      Status Code (uint16 LE)
6       11     Method (null-padded ASCII, e.g. "LOGINLIST\0\0")
17      1      Data Type (0 = BSON)
18      4      Body Size (uint32 LE)
22      ...    Body (BSON document)
```

The method field is a fixed 11 bytes, null-padded -- so `"PING"` is stored as `50 49 4e 47 00 00 00 00 00 00 00`. Every command and response uses the same structure. A client sends `LOGINLIST` with an auth token in the body; the server responds with a `LOGINLIST` packet whose body contains channel data. The packet ID ties requests to responses so concurrent requests can be multiplexed over one connection.

The implementation is clean:

```go
// loco/packet.go
func EncodePacket(p *Packet) ([]byte, error) {
    buf := make([]byte, HeaderSize+len(bodyBytes))
    binary.LittleEndian.PutUint32(buf[0:4], p.ID)
    binary.LittleEndian.PutUint16(buf[4:6], p.StatusCode)
    copy(buf[6:17], methodToBytes(p.Method))
    buf[17] = p.DataType
    binary.LittleEndian.PutUint32(buf[18:22], uint32(len(bodyBytes)))
    copy(buf[HeaderSize:], bodyBytes)
    return buf, nil
}
```

These packets ride over an encrypted connection. The client generates a random 16-byte AES key, encrypts it with the server's RSA public key (hardcoded in the client), and sends it as the first message on the TCP connection:

```
[encrypted_key_len : u32 LE]
[rsa_type          : u32 LE]   ← identifies the RSA padding scheme
[aes_type          : u32 LE]   ← identifies the AES cipher mode
[RSA-OAEP encrypted AES key]
```

This is a bespoke key exchange -- no TLS, no noise protocol, just "here's an RSA-encrypted AES key, let's go." After the handshake, every packet on the wire is wrapped in an encryption envelope:

```
[total_size : u32 LE]
[16-byte IV]                   ← random per packet
[AES-128-CFB encrypted LOCO packet]
```

The booking step (first hop) is the exception: it uses standard TLS, with plain unencrypted LOCO packets riding inside the TLS tunnel.

## Wall 1: The Shell Ate My Password

The first thing we tried was a curl-based login. KakaoTalk's HTTP auth endpoint accepts an email and password over a standard form POST:

```bash
curl -X POST "https://katalk.kakao.com/win32/account/login.json" \
  -d "email=...&password=some-fake-password!"
```

Status 12. Wrong credentials. We triple-checked the email. We tried URL-encoding. We tried different Content-Type headers.

The password is `some-fake-password!`. The culprit is the trailing `!`. In zsh (the default macOS shell), `!` triggers [history expansion](https://zsh.sourceforge.io/Doc/Release/Expansion.html#History-Expansion) -- `!` followed by a string recalls the last command starting with that string. Even inside double quotes, zsh expands `!`. The server received `some-fake-password\!` -- with a literal backslash.

This wasted an embarrassing amount of time before we realized the fix: stop using shell scripts entirely and write a Go program that reads `.env` directly via `os.ReadFile`, bypassing shell interpretation completely.

```go
func loadEnv(path string) {
    data, _ := os.ReadFile(path)
    for _, line := range strings.Split(string(data), "\n") {
        k, v, ok := strings.Cut(line, "=")
        if ok { os.Setenv(k, v) }
    }
}
```

## Wall 2: Which Agent? Which Endpoint?

KakaoTalk uses the term **agent** to identify which platform the client is running on. Each agent has its own HTTP endpoint path, User-Agent format, and anti-tamper hash. The official KakaoTalk clients exist for Windows (`win32`), macOS (`mac`), and Android (`android`). Our SDK pretends to be one of these -- we're a "sub-device," the same class as the official desktop clients that supplement the primary phone app.

node-kakao impersonates the Windows desktop client (`win32`). We tried that first, then systematically tested all combinations:

| login_id | agent | status |
|----------|-------|--------|
| email    | win32 | -100   |
| phone    | win32 | -100   |
| phone    | mac   | -100   |
| **email**| **mac**| **-100** |

All returned -100 (`NEED_DEVICE_AUTH`), which actually means the credentials are accepted but the device isn't registered yet. That's progress. But through later testing we learned that **only `email + mac` actually completes the full login flow.** The `win32` agent and phone-number login silently fail at the device registration step -- they return -100 forever, even after registration, without any error message explaining why.

The auth headers differ per agent type. Each builds a different User-Agent string:

```go
func getUserAgent(agent, version, osVersion, language string) string {
    switch agent {
    case "mac":     return fmt.Sprintf("KT/%s Mc/%s %s", version, osVersion, language)
    case "android": return fmt.Sprintf("KT/%s An/%s %s", version, osVersion, language)
    default:        return fmt.Sprintf("KT/%s Wd/%s %s", version, osVersion, language)
    }
}
// e.g. "KT/26.1.4 Mc/26.2 ko"
```

And the **XVC hash** -- a request-signing header that KakaoTalk uses to verify the client isn't tampered with -- uses different seed strings per agent. XVC is computed by hashing a formatted string with SHA-512 and taking the first 16 hex characters. The seed strings are hardcoded in the official clients:

```go
const (
    xvcPatternWin32 = "ARTHUR|%s|RUZ|%s|%s"   // UA, email, UUID
    xvcPatternMac   = "PITT|%s|%s|%s|INORAN"   // UA, email, UUID
)
hash := sha512.Sum512([]byte(fmt.Sprintf(xvcPatternMac, userAgent, email, deviceUUID)))
xvc := fmt.Sprintf("%x", hash)[:16]
```

If the XVC doesn't match what the server expects for your User-Agent, the request is rejected. Getting the agent wrong means every subsequent header computation is wrong too.

## The Device Registration Gauntlet

KakaoTalk's security model is phone-centric. Your phone is the **primary device** -- it's always logged in. Desktop and tablet clients are **sub-devices** that need explicit approval from the primary device before they can access the account. This is similar to WhatsApp Web requiring you to scan a QR code with your phone, except KakaoTalk uses a 4-digit passcode flow:

1. `POST /mac/account/passcodeLogin/cancel` -- clear any pending request
2. `POST /mac/account/passcodeLogin/generate` -- the server returns a 4-digit passcode and pushes a notification to the phone app
3. The user opens the notification on their phone, sees the passcode, and confirms it within 60 seconds
4. `POST /mac/account/passcodeLogin/registerDevice` -- tells the server the device is approved
5. `POST /mac/account/login.json` -- finally issues an access token

During development, we ran this flow dozens of times. Doing step 3 manually -- unlock phone, open KakaoTalk, find the notification, tap through three screens, enter the code -- was excruciating. So we automated it with ADB (Android Debug Bridge), driving a KakaoTalk instance running in an Android emulator.

We used `uiautomator dump` to capture the screen layout as XML, parsed it with Python to find button coordinates, then replayed tap sequences:

```bash
# Scroll to bottom of the KakaoTalk chat, tap "Enter the security verification code" button
adb shell input swipe 640 2400 640 400 200
adb shell input tap 565 2514   # coordinates found via uiautomator dump
# Wait for verification screen to load, type passcode, tap OK
adb shell input tap 640 697    # tap the text input field
adb shell input text "9557"    # type the 4-digit passcode
adb shell input tap 640 958    # tap OK button
```

The coordinates came from parsing the XML dump:

```python
tree = ET.parse('/tmp/ui.xml')
for node in tree.getroot().iter():
    text = node.get('text', '')
    bounds = node.get('bounds', '')
    if text == 'Enter the security verification code':
        # bounds="[266,2457][864,2571]" → center = (565, 2514)
```

When it worked, the phone showed:

```
'Successfully logged in'
'You are successfully logged in on amso-bridge.'
```

The cruel part: **each `login.json` call with `forced:true` consumes the device registration**. The `forced` flag tells the server "log me in even if another sub-device is already active" -- but it also invalidates the device approval. Every time you want a fresh token, you re-do the entire passcode dance. This matters later.

## First Login Success

```json
{
  "userId": 123456789,
  "access_token": "<redacted>",
  "refresh_token": "<redacted>",
  "status": 0
}
```

We have a token. Now for the hard part: the three-hop LOCO connection.

## Booking: GETCONF Over TLS

The first hop discovers where to connect next. The client sends a `GETCONF` command to a well-known booking server, which returns a list of checkin servers.

This is the only step that uses standard TLS -- the LOCO packets inside are unencrypted (the TLS tunnel provides the encryption). Think of it like a DNS lookup: "given my app version and network type, which checkin server should I talk to?"

```go
conn, err := tls.Dial("tcp", "booking-loco.kakao.com:443", &tls.Config{})
// Send GETCONF packet with app version, language, network type
// Receive response with checkin server host/port
```

### Wall 3: The Booking Parser

The response came back, but our parser choked:

```
cannot decode array into string
```

node-kakao treats `ticket.lsl` (the checkin server host list) as a single string. In the actual response, it's a JSON array of hostnames -- KakaoTalk can return multiple checkin servers for failover:

```go
// Wrong (from node-kakao's structure):
Ticket struct { Host string `bson:"lsl"` }

// Right:
Ticket struct { Hosts []string `bson:"lsl"` }
```

And the port? node-kakao reads it from `ticket.lslp`. That field doesn't exist in the response. The ports are nested under a different key entirely:

```go
// Wrong: Ticket struct { Port int `bson:"lslp"` }   ← field doesn't exist

// Right:
Wifi struct { Ports []int `bson:"ports"` }
```

After fixing both: `Checkin server: ticket-loco.kakao.com:995`

## Checkin: CHECKIN Over Encrypted TCP

The second hop determines your main LOCO server. The client opens a raw TCP connection to the checkin server, performs the RSA/AES key exchange handshake, and sends a `CHECKIN` command containing the user ID and app version. The server responds with the IP and port of the main LOCO server assigned to this user.

This is where the custom encryption layer kicks in. No more TLS -- from here on, every byte on the wire is encrypted with the AES key we exchanged during the handshake.

### Wall 4: The RSA Key

Every checkin attempt died immediately after the handshake:

```
EOF
connection reset by peer
read: connection reset by peer
```

The server received our handshake, couldn't decrypt the AES key (because we encrypted it with the wrong RSA public key), and dropped the connection. There's no error message -- an invalid handshake just gets you a TCP reset.

We tried everything we could think of without questioning the key itself: different hosts from the booking response array, different ports, writing the handshake as one `write()` call vs three separate calls (in case TCP segmentation mattered). All EOF.

The breakthrough came from decompiling the KakaoTalk Android APK (v26.1.3) with [JADX](https://github.com/skylot/jadx), a Java decompiler. In `kq/d.java` -- an obfuscated class that turned out to be the `SecureLayer` implementation:

```java
// kq/d.java — RSAPublicKeySpec constructor
new RSAPublicKeySpec(
    new BigInteger("A3B076E8C445851F19A670C231AAC6DB42EFD09717D060...", 16),
    BigInteger.valueOf(3L)
);
```

This was a completely different modulus than what node-kakao had. **The RSA public key had been rotated** since node-kakao was last updated. And the handshake type identifier -- a uint32 in the handshake that tells the server which RSA padding scheme you used -- had changed from `12` to `16`:

```java
// kq/EnumC33654b.java — encryption type enum
AES_CBC128(1), AES_CFB128(2), AES_GCM128(3);
```

```go
// Our old code (from node-kakao):
rsaTypeOAEPSHA1 uint32 = 12

// What the APK actually uses:
rsaTypeOAEPSHA1 uint32 = 16
```

We constructed the RSA key directly from the modulus and exponent we found in the APK, bypassing PEM entirely:

```go
const locoRSAModulus = "A3B076E8C445851F19A670C231AAC6DB..."

func init() {
    n := new(big.Int)
    n.SetString(locoRSAModulus, 16)
    locoRSAKey = &rsa.PublicKey{N: n, E: 3}
}
```

With the correct key and handshake type, checkin worked on the first try:

```
Main LOCO server: <checkin-ip>:995
```

A valid response. Real BSON data with IPv4 and IPv6 addresses, cache expiry times, supplementary server hosts. The decryption was working.

## LOGINLIST: The Final Boss

The third and final hop: connect to the main LOCO server (another encrypted TCP connection, another RSA/AES handshake), and send `LOGINLIST` -- the command that authenticates the session and returns the user's channel list. Once `LOGINLIST` succeeds, the connection becomes a persistent session that receives real-time push events (new messages, kicks, server migrations).

```go
session.Request("LOGINLIST", bson.M{
    "oauthToken":  token,
    "appVer":      "26.1.4",
    "prtVer":      "1",       // protocol version, always "1"
    "os":          "mac",     // agent type
    "dtype":       2,         // device type: 2 = sub-device
    "ntype":       0,         // network type: 0 = WiFi
    "MCCMNC":      "999",    // mobile carrier code: "999" = PC/non-mobile
    "duuid":       deviceUUID,
    "chatIds":     bson.A{},  // known channel IDs (empty = first login)
    "maxIds":      bson.A{},  // last-seen message IDs per channel
    "lastTokenId": int64(0),  // pagination cursor
    "revision":    0,         // incremental sync revision
    "rp":          nil,       // unknown, always null
})
```

First attempt: status -203. Missing `duuid` field -- we'd been passing an empty string for the device UUID. Every LOGINLIST parameter matters.

Fixed that. Next attempt: status -950 (token expired). We'd spent too long debugging between getting the token and using it. Back to the passcode registration dance -- generate a new passcode, automate the emulator, register, login, try again.

Got a fresh token. Next attempt: **status 0**. "Connected and authenticated!" But then:

```
loco: read error: loco: read size: EOF
List channels error: talk: LCHATLIST: loco: session closed
```

The server returned a response and immediately closed the connection. But it said status 0 -- success. What?

### Wall 5: Header Status vs Body Status

We added hex dumping to the decryption layer -- one `log.Printf` to print every decrypted packet as a hex string before parsing:

```
recv 39 bytes plaintext:
  0100000000004c4f47494e4c4953540000001100000011000000
  10737461747573004afcffff00
```

Breaking down the 22-byte LOCO header:

```
01000000     → Packet ID: 1
0000         → StatusCode: 0        ← this is what we were checking
4c4f47494e4c495354 0000 → Method: "LOGINLIST"
00           → DataType: BSON
11000000     → Body Size: 17 bytes
```

The header's StatusCode is 0. Our code checked `resp.StatusCode != 0` and concluded "success." But the 17-byte BSON body tells a different story:

```
11000000                      → BSON document size: 17
  10                          → type: int32
  737461747573 00             → key: "status\0"
  4afcffff                    → value: 0xfffffc4a (little-endian) = -950
00                            → document terminator
```

`{status: -950}`. Token expired.

The LOCO packet header has a `StatusCode` field (uint16 at offset 4). The BSON body *also* has a `status` field (int32). **They are completely independent values.** The header status is always 0 -- it's apparently vestigial or used for something else. The real application-level status is in the BSON body.

Our code was checking the wrong one:

```go
// Wrong -- checks the uint16 header status (always 0):
if resp.StatusCode != 0 { ... }

// Right -- checks the int32 BSON body status:
var parsed struct { Status int32 `bson:"status"` }
bson.Unmarshal(resp.Body, &parsed)
if parsed.Status != 0 { ... }
```

We'd been reading "success" from the header while the body screamed "your token expired." The server dutifully closed the connection after sending its -950 rejection, and we blamed the EOF instead of looking at what the server actually said.

This bug was invisible without the hex dump. The BSON parser happily deserialized `{status: -950}` into our response struct, but we never looked at that field because the header had already told us "everything's fine."

## Breakthrough

One more trip through the registration gauntlet. Fresh passcode, emulator automation, register, login, immediately connect before the token can expire:

```
--- Booking ---
Checkin server: ticket-loco.kakao.com:995

--- Checkin ---
Main LOCO server: <loco-ip>:995

--- LOGINLIST ---
Connected and authenticated!

Found 2 channel(s):
  [0] id=<channel-id-1> type=MultiChat members=6
  [1] id=<channel-id-2> type=PlusChat members=2

Listening for messages (Ctrl+C to quit)...
```

3,701 bytes of LOGINLIST response. Real channel data. A 6-person group chat (`MultiChat`). A channel with KakaoTalk's official notification account (`PlusChat` -- KakaoTalk's equivalent of a verified business account). The session stays alive, receiving `BLSYNC` push events (block-list sync, sent periodically by the server).

The interactive client works end to end:

```
--- Interactive Mode ---
Commands:
  send <channelID> <message>
  channels
  history <channelID>
  quit

> quit
Disconnecting...
Done.
```

## The Final Stack

```
amso/
  crypto/crypto.go       73 lines   AES-128-CFB, RSA-OAEP key exchange
  loco/packet.go         95 lines   22-byte header codec
  loco/secure.go        161 lines   encrypted conn, handshake
  loco/session.go       196 lines   request/response matching, ping loop
  auth/auth.go          243 lines   HTTP login, device registration
  auth/xvc.go            30 lines   XVC anti-tamper hash
  network/booking.go    108 lines   GETCONF over TLS
  network/checkin.go     80 lines   CHECKIN over encrypted TCP
  network/conn.go       139 lines   booking → checkin → LOGINLIST orchestrator
  talk/client.go        401 lines   high-level client, event dispatch
  talk/channel.go       178 lines   channel listing, members, history
  talk/chat.go           47 lines   message types
  talk/events.go         54 lines   event handler types
```

The core SDK is ~1,800 lines. The remaining ~1,900 lines are test commands and debug tools -- one-off programs we wrote along the way to poke at individual protocol steps, dump responses, and automate the emulator.

## The MITM Dead End

Before decompiling the APK, we tried the obvious approach: man-in-the-middle the KakaoTalk client to watch its traffic and learn the protocol by example.

The plan was straightforward. Run [mitmproxy](https://mitmproxy.org/) on localhost, install its CA certificate as a trusted root, and route KakaoTalk's HTTPS traffic through it. We'd see every HTTP request -- the login endpoint, the headers, the exact form fields -- without guessing.

```bash
# Install mitmproxy CA as trusted root
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.mitmproxy/mitmproxy-ca-cert.pem

# Start mitmdump, launch KakaoTalk through the proxy
export https_proxy=http://127.0.0.1:8080
open /Applications/KakaoTalk.app
```

KakaoTalk refused to connect. No requests appeared in mitmdump. The app uses **certificate pinning** -- it ships with a hardcoded copy of the expected server certificate (or its public key hash) and rejects any TLS connection where the certificate doesn't match, even if the system trusts the CA. Our mitmproxy CA cert was trusted by macOS, but KakaoTalk ignored that entirely.

We tried the Android emulator next, with [Frida](https://frida.re/) -- a dynamic instrumentation toolkit that can inject JavaScript into running processes. The idea: hook into KakaoTalk's OkHttp client at runtime and bypass the certificate pinning checks.

```javascript
// Frida script: bypass OkHttp CertificatePinner
var CertificatePinner = Java.use("okhttp3.CertificatePinner");
CertificatePinner.check.overload("java.lang.String", "java.util.List")
    .implementation = function(hostname, peerCertificates) {
        console.log("[*] CertificatePinner.check bypassed for: " + hostname);
        return;  // skip validation
    };
```

This also failed. KakaoTalk uses ProGuard/R8 obfuscation, which renames classes and methods at compile time. The class `okhttp3.CertificatePinner` doesn't exist under that name in the APK -- it's been renamed to something like `kq.a` or `sr.b`. We tried enumerating all loaded classes matching `kakao` or `loco` patterns, but the sheer number of obfuscated classes made it impractical to find the right hooks.

The Frida approach could theoretically work with enough effort -- map every obfuscated class, find the one that does certificate validation, hook it. But at that point, decompiling the APK with JADX and reading the (obfuscated but still comprehensible) Java source was faster and gave us everything we needed: the RSA key, the handshake type, the XVC seeds, the endpoint paths.

The LOCO protocol itself (the encrypted TCP layer after login) wouldn't benefit from MITM anyway. It's a bespoke binary protocol with its own encryption -- not HTTP, not TLS. The only way to understand it is to read the code that implements it.

## What node-kakao Got Wrong (For Us)

[node-kakao](https://github.com/storycraft/node-kakao) is the most complete open-source LOCO implementation. It gave us the protocol structure, the command names, the BSON field layouts. But it hasn't been actively maintained against recent KakaoTalk server changes, and several assumptions it makes are now wrong:

| What | node-kakao | Reality (Feb 2026) |
|------|------------|-------------------|
| RSA public key | `0F3188...` | `A3B076...` (rotated) |
| Handshake RSA type | 12 | 16 |
| `ticket.lsl` | string | `[]string` (array) |
| Checkin port field | `ticket.lslp` | `wifi.ports[0]` |
| LOCO response status | packet header | BSON body `status` field |

The RSA key rotation alone made every encrypted connection fail silently with EOF -- no error message, no negotiation, just a TCP reset. Without decompiling the APK to extract the current key, we'd still be staring at `connection reset by peer`.

## Lessons

**Hex dump everything.** The moment we added `log.Printf("recv %d bytes: %s", len(plaintext), hex.EncodeToString(plaintext))` to the decryption layer, the header-vs-body status bug became obvious. We'd spent hours treating EOF as a connection problem when it was an authentication problem. The bytes don't lie -- but you have to look at them.

**Reference implementations expire.** node-kakao gave us the 80% of the protocol that doesn't change: packet format, command names, encryption scheme, BSON field conventions. But the 20% that does change -- keys, type constants, response field layouts -- was enough to make nothing work. The APK decompile was non-negotiable.

**Automate the annoying parts.** We ran the passcode registration flow ~10 times during debugging. Without ADB automation, each attempt would've been 2-3 minutes of manual tapping through the KakaoTalk UI on the emulator. With it, the entire flow -- generate passcode, navigate to verification screen, type code, tap OK -- takes 8 seconds.

**Tokens are ephemeral.** KakaoTalk access tokens expire within minutes, and each `forced` login consumes the device registration. A 5-minute debugging detour between getting a token and trying LOGINLIST means the token is dead and you need to start from the passcode flow. We learned to script the entire pipeline -- register, login, connect -- as one unbroken sequence.

## Fixing the Registration Loop

The biggest developer-experience problem during all of this was the **device registration loop**. Every call to `login.json` with `forced:true` consumed the device registration, which meant every test run required the full passcode-on-phone dance: generate passcode, switch to the emulator, navigate to the verification screen, enter the code, tap confirm, race back to the terminal before the token expired. During a debugging session, we'd burn through this cycle 5-10 times in an hour.

The root cause was a single hardcoded boolean:

```go
Forced: true,
```

The `forced` flag tells the server "log me in even if another sub-device session exists." It's the sledgehammer approach -- it always works, but it invalidates the device's registration as a side effect. Without `forced`, the server checks whether the device is already registered and issues a token without consuming the registration. The device stays approved for future logins.

We'd originally used `forced:true` everywhere because it was the only thing that worked during initial development -- before the device was registered at all, `forced:false` returns -100 (`NEED_DEVICE_AUTH`), and we kept it set to `true` out of cargo-cult habit even after registration succeeded.

The fix was three changes:

**1. New passcode endpoints.** The old form-encoded `request_passcode.json` and `register_device.json` endpoints had started returning -400 (deprecated). KakaoTalk had migrated to JSON-based `passcodeLogin/*` endpoints:

```go
// Old (broken):
POST /mac/account/request_passcode.json  → -400
POST /mac/account/register_device.json   → -400

// New (working):
POST /mac/account/passcodeLogin/cancel           → clear pending
POST /mac/account/passcodeLogin/generate          → returns passcode
POST /mac/account/passcodeLogin/registerDevice    → poll until confirmed
```

The new endpoints use JSON request bodies instead of form-encoded, but still require the same auth headers (A, X-VC, User-Agent). The `generate` endpoint returns a passcode that the user confirms on their phone, then `registerDevice` is polled until the server acknowledges the confirmation.

**2. Default to `forced:false`.** The `Login()` method now defaults to `Forced: false`. A new `LoginWithOptions` method exposes the flag for callers who explicitly need it, with a doc comment warning that it burns the registration:

```go
type LoginOptions struct {
    Forced bool // WARNING: burns device registration
}

func (c *Client) Login(email, password, deviceUUID, deviceName string) error {
    return c.LoginWithOptions(email, password, deviceUUID, deviceName,
        LoginOptions{Forced: false})
}
```

**3. Token refresh doesn't burn registration.** The `RefreshSession()` fallback path -- which fires when a token refresh fails and the client needs to do a full re-login -- was calling `Login()` (which previously used `forced:true`). Now it explicitly passes `Forced: false`. If the device is still registered, the re-login succeeds silently. If not, the caller gets a clean -100 error and can run the passcode flow.

The result: register the device once, then run test-flow as many times as you want without touching the phone. The access token from `login.json` with `forced:false` works just like one from `forced:true` -- same expiry, same permissions, same LOCO session behavior. The only difference is the device registration survives.
