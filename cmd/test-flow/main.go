// Interactive test that walks through the full KakaoTalk connection flow step by step.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/auth"
	"github.com/jusunglee/amso/network"
	"github.com/jusunglee/amso/talk"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== KakaoTalk LOCO Protocol Test ===")
	fmt.Println()

	// Step 0: Gather credentials from env vars or prompt.
	// Use --test flag or TEST=1 env to use test account.
	loadEnvFile(".env")

	useTest := os.Getenv("TEST") == "1"
	for _, arg := range os.Args[1:] {
		if arg == "--test" || arg == "-test" {
			useTest = true
		}
	}

	var email, password, deviceUUID string
	if useTest {
		fmt.Println("*** Using TEST account (juicepack) ***")
		email = os.Getenv("KAKAO_EMAIL_TEST")
		password = os.Getenv("KAKAO_PASSWORD_TEST")
		deviceUUID = os.Getenv("KAKAO_DEVICE_UUID_TEST")
	} else {
		email = os.Getenv("KAKAO_EMAIL")
		password = os.Getenv("KAKAO_PASSWORD")
		deviceUUID = os.Getenv("KAKAO_DEVICE_UUID")
	}

	if email == "" {
		email = prompt(reader, "KakaoTalk email")
	} else {
		fmt.Printf("Email: %s (from env)\n", email)
	}

	if password == "" {
		password = prompt(reader, "KakaoTalk password")
	} else {
		fmt.Println("Password: *** (from env)")
	}

	if deviceUUID == "" {
		deviceUUID = generateUUID()
		fmt.Printf("Generated device UUID: %s\n", deviceUUID)
		fmt.Println("(Save this UUID — reuse it to avoid re-registering the device)")
	} else {
		fmt.Printf("Using device UUID from env: %s\n", deviceUUID)
	}
	fmt.Println()

	deviceName := "amso-bridge"

	// Step 1: HTTP Auth (or use saved token from env).
	fmt.Println("--- Step 1: HTTP Authentication ---")

	var accessToken string
	var userID int64

	savedTokenKey := "KAKAO_ACCESS_TOKEN"
	savedUserKey := "KAKAO_USER_ID"
	if useTest {
		savedTokenKey = "KAKAO_ACCESS_TOKEN_TEST"
		savedUserKey = "KAKAO_USER_ID_TEST"
	}

	savedToken := os.Getenv(savedTokenKey)
	var refreshToken string
	if savedToken != "" {
		accessToken = savedToken
		fmt.Sscanf(os.Getenv(savedUserKey), "%d", &userID)
		fmt.Printf("Using saved token from env (userID=%d)\n", userID)
	} else {
		loginResp, err := auth.Login(auth.LoginRequest{
			Email:      email,
			Password:   password,
			DeviceUUID: deviceUUID,
			DeviceName: deviceName,
			Forced:     false,
		})
		if err != nil {
			fmt.Printf("Login error: %v\n", err)
			if loginResp != nil {
				fmt.Printf("Status: %d\n", loginResp.Status)
			}

			// Status -100 = device not registered.
			if loginResp != nil && (loginResp.Status == -100 || loginResp.Status == -101) {
				fmt.Println()
				fmt.Println("Device not registered. Starting passcode registration flow...")
				fmt.Println()

				ac := auth.NewAuthClient(email, password, deviceUUID, deviceName)

				// Cancel any pending passcode flow.
				fmt.Println("Cancelling any pending passcode flow...")
				if cancelErr := ac.CancelPasscode(); cancelErr != nil {
					fmt.Printf("  (cancel: %v)\n", cancelErr)
				}

				// Generate a new passcode.
				fmt.Println("Generating passcode...")
				genResp, genErr := ac.GeneratePasscode()
				if genErr != nil {
					log.Fatalf("Failed to generate passcode: %v", genErr)
				}

				fmt.Println()
				fmt.Printf("  Passcode: %s (expires in %ds)\n", genResp.Passcode, genResp.RemainingSeconds)
				fmt.Println()
				fmt.Println("Open KakaoTalk on your phone and confirm this passcode.")
				prompt(reader, "Press Enter after confirming on your phone")

				// Poll for device registration.
				fmt.Println("Polling for device registration...")
				deadline := time.Now().Add(60 * time.Second)
				for time.Now().Before(deadline) {
					regResp, regErr := ac.PollRegisterDevice(genResp.Passcode, true)
					if regErr == nil {
						fmt.Printf("  Device registered! (remainingSeconds=%d)\n", regResp.RemainingSeconds)
						break
					}
					fmt.Printf("  Waiting... (status=%d)\n", regResp.Status)
					time.Sleep(3 * time.Second)
				}

				fmt.Println()
				fmt.Println("Retrying login...")
				loginResp, err = auth.Login(auth.LoginRequest{
					Email:      email,
					Password:   password,
					DeviceUUID: deviceUUID,
					DeviceName: deviceName,
					Forced:     false,
				})
				if err != nil {
					log.Fatalf("Login retry failed: %v", err)
				}
			} else {
				log.Fatalf("Cannot proceed without successful login")
			}
		}
		accessToken = loginResp.AccessToken
		refreshToken = loginResp.RefreshToken
		userID = loginResp.UserID
		fmt.Printf("OK! UserID=%d Token=%s...\n", userID, accessToken[:min(20, len(accessToken))])

		// Print tokens so user can save them to .env for next run.
		fmt.Println()
		fmt.Println("=== Save these to .env to skip login next time ===")
		fmt.Printf("%s=%s\n", savedTokenKey, accessToken)
		fmt.Printf("%s=%d\n", savedUserKey, userID)
		if refreshToken != "" {
			fmt.Printf("KAKAO_REFRESH_TOKEN=%s\n", refreshToken)
		}
		fmt.Println("===================================================")
	}
	fmt.Println()

	// Step 2: Booking.
	fmt.Println("--- Step 2: Booking (GETCONF) ---")
	cfg := network.DefaultConfig()
	booking, err := network.RequestBooking(cfg)
	if err != nil {
		log.Fatalf("Booking failed: %v", err)
	}
	fmt.Printf("OK! Checkin server: %s:%d\n", booking.CheckinHost, booking.CheckinPort)
	fmt.Println()

	// Step 3: Checkin.
	fmt.Println("--- Step 3: Checkin ---")
	checkin, err := network.RequestCheckin(booking.CheckinHost, booking.CheckinPort, cfg, userID)
	if err != nil {
		log.Fatalf("Checkin failed: %v", err)
	}
	fmt.Printf("OK! Main LOCO server: %s:%d\n", checkin.Host, checkin.Port)
	fmt.Println()

	// Step 4: Full client login + session.
	fmt.Println("--- Step 4: Full Client Session (LOGINLIST) ---")
	client := talk.NewClient()

	// Register all event handlers including new ones.
	client.Handlers.OnMessage = func(ev talk.MessageEvent) {
		fmt.Printf("[MSG] ch=%d from=%d type=%d: %s\n",
			ev.ChannelID, ev.Log.SenderID, ev.Log.Type, ev.Log.Text)
		// If it's a photo/file, show attachment info
		if ev.Log.Type == talk.ChatTypePhoto && len(ev.Log.Attachment) > 0 {
			att, err := talk.ParsePhotoAttachment(ev.Log.Attachment)
			if err == nil {
				fmt.Printf("  [PHOTO] %dx%d size=%d url=%s\n", att.Width, att.Height, att.Size, talk.DownloadURL(att.Path))
			}
		} else if ev.Log.Type == talk.ChatTypeFile && len(ev.Log.Attachment) > 0 {
			att, err := talk.ParseFileAttachment(ev.Log.Attachment)
			if err == nil {
				fmt.Printf("  [FILE] name=%s size=%d url=%s\n", att.Name, att.Size, talk.DownloadURL(att.Path))
			}
		}
	}
	client.Handlers.OnKick = func(ev talk.KickEvent) {
		fmt.Printf("[KICK] reason=%d\n", ev.Reason)
	}
	client.Handlers.OnChannelJoin = func(ev talk.ChannelJoinEvent) {
		fmt.Printf("[JOIN] ch=%d user=%d\n", ev.ChannelID, ev.UserID)
	}
	client.Handlers.OnChannelLeave = func(ev talk.ChannelLeaveEvent) {
		fmt.Printf("[LEAVE] ch=%d user=%d\n", ev.ChannelID, ev.UserID)
	}
	client.Handlers.OnReadReceipt = func(ev talk.ReadReceiptEvent) {
		fmt.Printf("[READ] ch=%d user=%d watermark=%d\n", ev.ChannelID, ev.UserID, ev.Watermark)
	}
	client.Handlers.OnTyping = func(ev talk.TypingEvent) {
		fmt.Printf("[TYPING] ch=%d user=%d\n", ev.ChannelID, ev.UserID)
	}
	client.Handlers.OnMessageDelete = func(ev talk.MessageDeleteEvent) {
		fmt.Printf("[DELETE] ch=%d logId=%d\n", ev.ChannelID, ev.LogID)
	}
	// Verbose catch-all: hex dump + BSON parse for unknown push types
	client.Handlers.OnRaw = func(method string, body []byte) {
		fmt.Printf("[PUSH] %s (%d bytes): %s\n", method, len(body), hex.EncodeToString(body[:min(64, len(body))]))
		var raw bson.M
		if err := bson.Unmarshal(body, &raw); err == nil {
			j, _ := json.MarshalIndent(raw, "  ", "  ")
			fmt.Printf("  %s\n", string(j))
		}
	}

	if err := client.LoginWithToken(accessToken, userID, deviceUUID); err != nil {
		log.Fatalf("Session login failed: %v", err)
	}
	fmt.Println("OK! Connected and authenticated.")
	fmt.Println()

	// Step 5: List channels.
	fmt.Println("--- Step 5: List Channels ---")
	channels, err := client.ListChannels()
	if err != nil {
		fmt.Printf("Failed to list channels: %v\n", err)
	} else {
		fmt.Printf("Found %d channel(s):\n", len(channels))
		for i, ch := range channels {
			fmt.Printf("  [%d] id=%d type=%s members=%d\n", i, ch.ID, ch.Type, ch.MemberCount)
		}
	}
	fmt.Println()

	// Step 6: Send a test message.
	fmt.Println("--- Step 6: Send Test Message ---")
	if len(channels) > 0 {
		targetCh := channels[0]
		for _, ch := range channels {
			if ch.Type == "MultiChat" || ch.Type == "OM" {
				targetCh = ch
				break
			}
		}

		testMsg := fmt.Sprintf("hello from amso (sent at %s)", time.Now().Format("15:04:05"))
		fmt.Printf("Sending to channel %d (%s): %q\n", targetCh.ID, targetCh.Type, testMsg)
		cl, err := client.SendText(targetCh.ID, testMsg)
		if err != nil {
			fmt.Printf("Send failed: %v\n", err)
		} else {
			fmt.Printf("OK! logId=%d chatId=%d\n", cl.LogID, cl.ChatID)
		}
	} else {
		fmt.Println("No channels available to send to.")
	}
	fmt.Println()

	// Step 7: Interactive mode.
	fmt.Println("--- Interactive Mode ---")
	fmt.Println("Commands:")
	fmt.Println("  send <channelID> <message>  — send a text message")
	fmt.Println("  typing <channelID>          — send typing indicator")
	fmt.Println("  members <channelID>         — list channel members")
	fmt.Println("  channels                    — list channels again")
	fmt.Println("  history <channelID>         — fetch recent messages")
	fmt.Println("  quit                        — disconnect and exit")
	fmt.Println()
	fmt.Println("Incoming events will be printed as they arrive.")
	fmt.Println()

	for {
		fmt.Print("> ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 3)
		cmd := parts[0]

		switch cmd {
		case "quit", "exit", "q":
			fmt.Println("Disconnecting...")
			client.Close()
			fmt.Println("Done.")
			return

		case "channels":
			chs, err := client.ListChannels()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				continue
			}
			for i, ch := range chs {
				fmt.Printf("  [%d] id=%d type=%s members=%d\n", i, ch.ID, ch.Type, ch.MemberCount)
			}

		case "members":
			if len(parts) < 2 {
				fmt.Println("Usage: members <channelID>")
				continue
			}
			var chID int64
			if _, err := fmt.Sscanf(parts[1], "%d", &chID); err != nil {
				fmt.Printf("Invalid channel ID: %s\n", parts[1])
				continue
			}
			members, err := client.GetChannelMembers(chID)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				for _, m := range members {
					fmt.Printf("  uid=%d nick=%q profile=%s status=%q\n",
						m.UserID, m.Nickname, m.ProfileURL, m.StatusMessage)
				}
			}

		case "typing":
			if len(parts) < 2 {
				fmt.Println("Usage: typing <channelID>")
				continue
			}
			var chID int64
			if _, err := fmt.Sscanf(parts[1], "%d", &chID); err != nil {
				fmt.Printf("Invalid channel ID: %s\n", parts[1])
				continue
			}
			if err := client.SendTyping(chID); err != nil {
				fmt.Printf("Typing error: %v\n", err)
			} else {
				fmt.Println("Typing indicator sent")
			}

		case "send":
			if len(parts) < 3 {
				fmt.Println("Usage: send <channelID> <message>")
				continue
			}
			var chID int64
			if _, err := fmt.Sscanf(parts[1], "%d", &chID); err != nil {
				fmt.Printf("Invalid channel ID: %s\n", parts[1])
				continue
			}
			msg := parts[2]
			cl, err := client.SendText(chID, msg)
			if err != nil {
				fmt.Printf("Send error: %v\n", err)
			} else {
				fmt.Printf("Sent! logId=%d\n", cl.LogID)
			}

		case "history":
			if len(parts) < 2 {
				fmt.Println("Usage: history <channelID>")
				continue
			}
			var chID int64
			if _, err := fmt.Sscanf(parts[1], "%d", &chID); err != nil {
				fmt.Printf("Invalid channel ID: %s\n", parts[1])
				continue
			}
			logs, err := client.SyncMessages(chID, 0, 20)
			if err != nil {
				fmt.Printf("History error: %v\n", err)
			} else {
				for _, l := range logs {
					fmt.Printf("  [%d] from=%d type=%d: %s\n", l.LogID, l.SenderID, l.Type, l.Text)
				}
			}

		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}
	}
}

func prompt(reader *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func generateUUID() string {
	b := make([]byte, 64)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// loadEnvFile reads a .env file and sets environment variables (won't overwrite existing ones).
func loadEnvFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}
}
