// Example KakaoTalk bot that logs in, lists channels, and echoes received messages.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jusunglee/amso/talk"
)

func main() {
	email := os.Getenv("KAKAO_EMAIL")
	password := os.Getenv("KAKAO_PASSWORD")
	deviceUUID := os.Getenv("KAKAO_DEVICE_UUID")
	deviceName := os.Getenv("KAKAO_DEVICE_NAME")

	if email == "" || password == "" || deviceUUID == "" {
		fmt.Fprintln(os.Stderr, "Usage: set KAKAO_EMAIL, KAKAO_PASSWORD, KAKAO_DEVICE_UUID, and optionally KAKAO_DEVICE_NAME")
		os.Exit(1)
	}
	if deviceName == "" {
		deviceName = "amso-client"
	}

	client := talk.NewClient()

	// Set up event handlers before login.
	client.Handlers.OnMessage = func(ev talk.MessageEvent) {
		log.Printf("[MSG] channel=%d sender=%d type=%d: %s",
			ev.ChannelID, ev.Log.SenderID, ev.Log.Type, ev.Log.Text)

		// Echo text messages back.
		if ev.Log.Type == talk.ChatTypeText && ev.Log.SenderID != client.UserID {
			_, err := client.SendText(ev.ChannelID, "echo: "+ev.Log.Text)
			if err != nil {
				log.Printf("Failed to echo: %v", err)
			}
		}
	}

	client.Handlers.OnKick = func(ev talk.KickEvent) {
		log.Printf("[KICK] reason=%d", ev.Reason)
		os.Exit(1)
	}

	client.Handlers.OnDisconnect = func(ev talk.DisconnectEvent) {
		log.Printf("[DISCONNECT] %v", ev.Err)
	}

	client.Handlers.OnChannelJoin = func(ev talk.ChannelJoinEvent) {
		log.Printf("[JOIN] channel=%d user=%d", ev.ChannelID, ev.UserID)
	}

	client.Handlers.OnChannelLeave = func(ev talk.ChannelLeaveEvent) {
		log.Printf("[LEAVE] channel=%d user=%d", ev.ChannelID, ev.UserID)
	}

	client.Handlers.OnRaw = func(method string, body []byte) {
		log.Printf("[RAW] method=%s len=%d", method, len(body))
	}

	log.Println("Logging in...")
	if err := client.Login(email, password, deviceUUID, deviceName); err != nil {
		log.Fatalf("Login failed: %v", err)
	}
	log.Printf("Logged in as user %d", client.UserID)

	// List channels.
	channels, err := client.ListChannels()
	if err != nil {
		log.Printf("Failed to list channels: %v", err)
	} else {
		log.Printf("Channels (%d):", len(channels))
		for _, ch := range channels {
			log.Printf("  id=%d type=%s members=%d", ch.ID, ch.Type, ch.MemberCount)
		}
	}

	// Wait for Ctrl+C.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	client.Close()
}
