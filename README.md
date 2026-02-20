# amso

A barebones Go SDK for the KakaoTalk LOCO protocol. Built as a foundation for a [mautrix-go](https://github.com/mautrix/go) bridge.

Based on the protocol work from [node-kakao](https://github.com/storycraft/node-kakao).

## Features

- **Authentication** — Email/password login, token refresh, device registration with passcode verification
- **LOCO protocol** — Binary packet codec, AES-128-CFB encrypted transport, RSA key exchange
- **Connection management** — Booking → checkin → session flow, automatic ping keepalive, reconnect on server change
- **Messaging** — Send text, replies, forwards; receive messages via event callbacks
- **Channels** — List channels, get info/members, sync message history, mark as read
- **Events** — Message, kick, disconnect, member join/leave, raw push handler

## Project Structure

```
crypto/          AES-128-CFB + RSA OAEP key exchange
loco/
  packet.go      LOCO packet codec (22-byte header + BSON body)
  secure.go      Encrypted connection (RSA handshake + AES read/write)
  session.go     Request/response matching, packet IDs, ping loop
auth/
  auth.go        HTTP login, device registration
  xvc.go         XVC auth header (SHA512)
network/
  booking.go     GETCONF → checkin server address
  checkin.go     CHECKIN → main LOCO server address
  conn.go        Full connection orchestrator
talk/
  client.go      High-level client (login, send, reconnect)
  events.go      Event types + handler registration
  channel.go     Channel operations (list, info, members, history)
  chat.go        Message types and structures
```

## Install

```
go get github.com/jusunglee/amso
```

## Quick Start

```go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/jusunglee/amso/talk"
)

func main() {
	client := talk.NewClient()

	client.Handlers.OnMessage = func(ev talk.MessageEvent) {
		fmt.Printf("channel=%d sender=%d: %s\n",
			ev.ChannelID, ev.Log.SenderID, ev.Log.Text)
	}

	err := client.Login(
		os.Getenv("KAKAO_EMAIL"),
		os.Getenv("KAKAO_PASSWORD"),
		os.Getenv("KAKAO_DEVICE_UUID"),
		"my-app",
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
}
```

## Interactive Test

A step-by-step test binary is included that walks through each protocol stage:

```bash
go run ./cmd/test-flow/
```

It will prompt for credentials, handle device registration if needed, and drop into an interactive shell for sending messages and viewing channels.

To reuse a registered device:

```bash
KAKAO_DEVICE_UUID=<saved-uuid> go run ./cmd/test-flow/
```

## Account Setup

You need a KakaoTalk account with an email linked:

1. Install KakaoTalk on a phone (or Android emulator)
2. Sign up with a phone number
3. Go to **Settings → Kakao Account → Link email** and set an email + password
4. Use that email/password with the SDK

## Dependencies

- [`go.mongodb.org/mongo-driver/bson`](https://pkg.go.dev/go.mongodb.org/mongo-driver/bson) — BSON encoding (LOCO wire format)
- Go standard library for everything else (crypto, networking, TLS)

## License

MIT
