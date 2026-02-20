// Interactive test that walks through the full KakaoTalk connection flow step by step.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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
	loadEnvFile(".env")

	email := os.Getenv("KAKAO_EMAIL")
	if email == "" {
		email = prompt(reader, "KakaoTalk email")
	} else {
		fmt.Printf("Email: %s (from env)\n", email)
	}

	password := os.Getenv("KAKAO_PASSWORD")
	if password == "" {
		password = prompt(reader, "KakaoTalk password")
	} else {
		fmt.Println("Password: *** (from env)")
	}

	deviceUUID := os.Getenv("KAKAO_DEVICE_UUID")
	if deviceUUID == "" {
		deviceUUID = generateUUID()
		fmt.Printf("Generated device UUID: %s\n", deviceUUID)
		fmt.Println("(Save this UUID — reuse it to avoid re-registering the device)")
	} else {
		fmt.Printf("Using device UUID from env: %s\n", deviceUUID)
	}
	fmt.Println()

	deviceName := "amso-test"

	// Step 1: HTTP Auth (or use saved token from env).
	fmt.Println("--- Step 1: HTTP Authentication ---")

	var accessToken string
	var userID int64

	savedToken := os.Getenv("KAKAO_ACCESS_TOKEN")
	if savedToken != "" {
		accessToken = savedToken
		fmt.Sscanf(os.Getenv("KAKAO_USER_ID"), "%d", &userID)
		fmt.Printf("Using saved token from env (userID=%d)\n", userID)
	} else {
		loginResp, err := auth.Login(auth.LoginRequest{
			Email:      email,
			Password:   password,
			DeviceUUID: deviceUUID,
			DeviceName: deviceName,
			Forced:     true,
		})
		if err != nil {
			fmt.Printf("Login error: %v\n", err)
			if loginResp != nil {
				fmt.Printf("Status: %d\n", loginResp.Status)
			}

			// Status -100 = device not registered.
			if loginResp != nil && (loginResp.Status == -100 || loginResp.Status == -101) {
				fmt.Println()
				fmt.Println("Device not registered. Starting device registration flow...")
				fmt.Println()

				ac := auth.NewAuthClient(email, password, deviceUUID, deviceName)

				// Request passcode — this triggers a push notification to the phone.
				fmt.Println("Requesting passcode (sends notification to phone)...")
				respBody, reqErr := ac.RequestPasscode()
				fmt.Printf("  request_passcode.json -> %s\n", string(respBody))
				if reqErr != nil {
					fmt.Printf("  HTTP error: %v\n", reqErr)
				}

				fmt.Println()
				fmt.Println("Check your KakaoTalk phone app for a verification notification.")
				fmt.Println("You should see a 4-digit code on your phone.")
				fmt.Println()

				input := prompt(reader, "Enter the 4-digit passcode from your phone (or 'skip' to retry login)")

				if input != "" && input != "skip" {
					// Register the device with the passcode.
					fmt.Println("Registering device with passcode...")
					respBody, reqErr = ac.RegisterDevice(input, true)
					fmt.Printf("  register_device.json -> %s\n", string(respBody))
					if reqErr != nil {
						fmt.Printf("  HTTP error: %v\n", reqErr)
					}
				}

				fmt.Println()
				fmt.Println("Retrying login...")
				loginResp, err = auth.Login(auth.LoginRequest{
					Email:      email,
					Password:   password,
					DeviceUUID: deviceUUID,
					DeviceName: deviceName,
					Forced:     true,
				})
				if err != nil {
					log.Fatalf("Login retry failed: %v", err)
				}
			} else {
				log.Fatalf("Cannot proceed without successful login")
			}
		}
		accessToken = loginResp.AccessToken
		userID = loginResp.UserID
		fmt.Printf("OK! UserID=%d Token=%s...\n", userID, accessToken[:min(20, len(accessToken))])
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
	client.Handlers.OnMessage = func(ev talk.MessageEvent) {
		fmt.Printf("[MSG] ch=%d from=%d type=%d: %s\n",
			ev.ChannelID, ev.Log.SenderID, ev.Log.Type, ev.Log.Text)
	}
	client.Handlers.OnKick = func(ev talk.KickEvent) {
		fmt.Printf("[KICK] reason=%d\n", ev.Reason)
	}
	client.Handlers.OnRaw = func(method string, body []byte) {
		fmt.Printf("[PUSH] %s (%d bytes)\n", method, len(body))
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
		// Pick the first MultiChat channel, or fall back to the first channel.
		targetCh := channels[0]
		for _, ch := range channels {
			if ch.Type == "MultiChat" {
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
	fmt.Println("  channels                     — list channels again")
	fmt.Println("  history <channelID>          — fetch recent messages")
	fmt.Println("  quit                         — disconnect and exit")
	fmt.Println()
	fmt.Println("Incoming messages will be printed as they arrive.")
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
