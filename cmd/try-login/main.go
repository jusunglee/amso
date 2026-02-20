package main

import (
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/jusunglee/amso/network"
	"github.com/jusunglee/amso/talk"
)

const baseURL = "https://katalk.kakao.com"

func main() {
	loadEnv(".env")
	email := os.Getenv("KAKAO_EMAIL")
	phone := os.Getenv("KAKAO_PHONE")
	password := os.Getenv("KAKAO_PASSWORD")
	uuid := os.Getenv("KAKAO_DEVICE_UUID")
	deviceName := "amso-bridge"

	loginID := phone
	if loginID == "" {
		loginID = email
	}

	version := "26.1.4"
	ua := fmt.Sprintf("KT/%s Mc/26.2 ko", version)
	aHeader := fmt.Sprintf("mac/%s/ko", version)
	xvcInput := fmt.Sprintf("PITT|%s|%s|%s|INORAN", ua, loginID, uuid)
	hash := sha512.Sum512([]byte(xvcInput))
	xvc := fmt.Sprintf("%x", hash[:8])

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run . <command>")
		fmt.Println("  cancel    - Cancel existing passcode request")
		fmt.Println("  generate  - Generate new passcode")
		fmt.Println("  register  - Register device (after phone confirms)")
		fmt.Println("  login     - Login with registered device")
		fmt.Println("  full      - Cancel + generate (then you confirm on phone)")
		fmt.Println("  connect   - Full flow: login + booking + checkin + LOGINLIST")
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "cancel":
		resp := doJSON(baseURL+"/mac/account/passcodeLogin/cancel", map[string]interface{}{
			"email": loginID, "password": password,
			"device": map[string]interface{}{"uuid": uuid},
		}, ua, aHeader, xvc)
		fmt.Printf("Cancel: %s\n", resp)

	case "generate":
		resp := doJSON(baseURL+"/mac/account/passcodeLogin/generate", map[string]interface{}{
			"email": loginID, "password": password,
			"device": map[string]interface{}{
				"name": deviceName, "uuid": uuid, "osVersion": "26.2",
			},
		}, ua, aHeader, xvc)
		fmt.Printf("Generate: %s\n", resp)

	case "register":
		resp := doJSON(baseURL+"/mac/account/passcodeLogin/registerDevice", map[string]interface{}{
			"email": loginID, "password": password,
			"device": map[string]interface{}{"uuid": uuid},
		}, ua, aHeader, xvc)
		fmt.Printf("Register: %s\n", resp)

	case "login":
		tryLogin(email, password, uuid, deviceName)

	case "full":
		resp := doJSON(baseURL+"/mac/account/passcodeLogin/cancel", map[string]interface{}{
			"email": loginID, "password": password,
			"device": map[string]interface{}{"uuid": uuid},
		}, ua, aHeader, xvc)
		fmt.Printf("Cancel: %s\n", resp)

		genResp := doJSON(baseURL+"/mac/account/passcodeLogin/generate", map[string]interface{}{
			"email": loginID, "password": password,
			"device": map[string]interface{}{
				"name": deviceName, "uuid": uuid, "osVersion": "26.2",
			},
		}, ua, aHeader, xvc)
		fmt.Printf("Generate: %s\n", genResp)

		var result struct {
			Status   int    `json:"status"`
			Passcode string `json:"passcode"`
		}
		json.Unmarshal([]byte(genResp), &result)
		if result.Status == 0 {
			fmt.Printf("\nPasscode: %s\n", result.Passcode)
			fmt.Println("Now confirm on phone, then run: go run ./cmd/try-login register")
			fmt.Println("Then run: go run ./cmd/try-login login")
		}

	case "connect":
		// Full connection flow: token → booking → checkin → LOGINLIST
		token := os.Getenv("KAKAO_ACCESS_TOKEN")
		if token == "" {
			// Try login if no saved token
			token, _ = doLogin(email, password, uuid, deviceName)
			if token == "" {
				fmt.Println("No token available. Run 'login' first and save to .env")
				return
			}
		}
		var userID int64
		fmt.Sscanf(os.Getenv("KAKAO_USER_ID"), "%d", &userID)
		if userID == 0 {
			fmt.Println("KAKAO_USER_ID not set. Run 'login' first and save to .env")
			return
		}
		fmt.Printf("Using token=%s... userID=%d\n\n", token[:20], userID)

		// Use mac-style config
		cfg := network.DefaultConfig()
		cfg.Agent = "mac"
		cfg.AppVersion = "26.1.4"
		cfg.OSVersion = "26.2"

		fmt.Println("--- Booking ---")
		booking, err := network.RequestBooking(cfg)
		if err != nil {
			fmt.Printf("Booking error: %v\n", err)
			return
		}
		fmt.Printf("Checkin server: %s:%d\n\n", booking.CheckinHost, booking.CheckinPort)

		fmt.Println("--- Checkin ---")
		checkin, err := network.RequestCheckin(booking.CheckinHost, booking.CheckinPort, cfg, userID)
		if err != nil {
			fmt.Printf("Checkin error: %v\n", err)
			return
		}
		fmt.Printf("Main LOCO server: %s:%d\n\n", checkin.Host, checkin.Port)

		fmt.Println("--- LOGINLIST ---")
		client := talk.NewClient()
		client.Config = cfg
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

		uuid := os.Getenv("KAKAO_DEVICE_UUID")
		if err := client.LoginWithToken(token, userID, uuid); err != nil {
			fmt.Printf("Session login failed: %v\n", err)
			return
		}
		fmt.Println("Connected and authenticated!")
		fmt.Println()

		channels, err := client.ListChannels()
		if err != nil {
			fmt.Printf("List channels error: %v\n", err)
		} else {
			fmt.Printf("Found %d channel(s):\n", len(channels))
			for i, ch := range channels {
				fmt.Printf("  [%d] id=%d type=%s members=%d\n", i, ch.ID, ch.Type, ch.MemberCount)
			}
		}

		fmt.Println("\nListening for messages (Ctrl+C to quit)...")
		select {} // block forever
	}
}

func doLogin(email, password, uuid, deviceName string) (token string, userID int64) {
	version := "26.1.4"
	ua := fmt.Sprintf("KT/%s Mc/26.2 ko", version)
	aHdr := fmt.Sprintf("mac/%s/ko", version)

	xvcInput := fmt.Sprintf("PITT|%s|%s|%s|INORAN", ua, email, uuid)
	hash := sha512.Sum512([]byte(xvcInput))
	xvc := fmt.Sprintf("%x", hash[:8])

	form := url.Values{
		"email":       {email},
		"password":    {password},
		"device_uuid": {uuid},
		"device_name": {deviceName},
		"os_version":  {"26.2"},
		"permanent":   {"true"},
		"forced":      {"true"},
	}

	endpoint := baseURL + "/mac/account/login.json"
	httpReq, _ := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("A", aHdr)
	httpReq.Header.Set("X-VC", xvc)
	httpReq.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		fmt.Printf("Login error: %v\n", err)
		return "", 0
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var loginResp struct {
		Status      int    `json:"status"`
		AccessToken string `json:"access_token"`
		UserID      int64  `json:"userId"`
	}
	json.Unmarshal(body, &loginResp)

	if loginResp.Status != 0 {
		fmt.Printf("Login failed: %s\n", string(body))
		return "", 0
	}

	return loginResp.AccessToken, loginResp.UserID
}

func tryLogin(email, password, uuid, deviceName string) {
	version := "26.1.4"
	ua := fmt.Sprintf("KT/%s Mc/26.2 ko", version)
	aHdr := fmt.Sprintf("mac/%s/ko", version)

	xvcInput := fmt.Sprintf("PITT|%s|%s|%s|INORAN", ua, email, uuid)
	hash := sha512.Sum512([]byte(xvcInput))
	xvc := fmt.Sprintf("%x", hash[:8])

	form := url.Values{
		"email":       {email},
		"password":    {password},
		"device_uuid": {uuid},
		"device_name": {deviceName},
		"os_version":  {"26.2"},
		"permanent":   {"true"},
		"forced":      {"true"},
	}

	endpoint := baseURL + "/mac/account/login.json"
	httpReq, _ := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("A", aHdr)
	httpReq.Header.Set("X-VC", xvc)
	httpReq.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		fmt.Printf("Login error: %v\n", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("Login: %s\n", string(body))
}

func doJSON(endpoint string, data map[string]interface{}, ua, aHeader, xvc string) string {
	jsonBytes, _ := json.Marshal(data)
	httpReq, _ := http.NewRequest("POST", endpoint, strings.NewReader(string(jsonBytes)))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("A", aHeader)
	httpReq.Header.Set("X-VC", xvc)
	httpReq.Header.Set("User-Agent", ua)
	httpReq.Header.Set("Accept", "*/*")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return fmt.Sprintf(`{"error":"%v"}`, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func loadEnv(path string) {
	data, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		os.Setenv(k, v)
	}
}
