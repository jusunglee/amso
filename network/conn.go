package network

import (
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/loco"
)

const (
	DefaultAgent      = "mac"
	DefaultAppVersion = "26.1.4"
	DefaultOSVersion  = "26.2"
	DefaultDeviceType = 2     // sub device
	DefaultNetType    = 0     // WIFI
	DefaultMCCMNC     = "999" // PC
	DefaultLanguage   = "ko"
)

// Config holds protocol configuration for the LOCO connection.
type Config struct {
	Agent       string
	AppVersion  string
	OSVersion   string
	DeviceType  int
	NetType     int
	MCCMNC      string
	Language    string
	DeviceModel string
}

// DefaultConfig returns a Config with sensible defaults for a PC/win32 client.
func DefaultConfig() *Config {
	return &Config{
		Agent:       DefaultAgent,
		AppVersion:  DefaultAppVersion,
		OSVersion:   DefaultOSVersion,
		DeviceType:  DefaultDeviceType,
		NetType:     DefaultNetType,
		MCCMNC:      DefaultMCCMNC,
		Language:    DefaultLanguage,
		DeviceModel: "",
	}
}

// LoginResult contains the data returned from a successful LOGINLIST command.
type LoginResult struct {
	Channels []bson.Raw // raw channel data from login
	Raw      bson.Raw   // full response
}

// Connect performs the full LOCO connection flow: booking → checkin → main session login.
// Returns an active Session ready for sending/receiving messages.
func Connect(accessToken string, userID int64, deviceUUID string, cfg *Config) (*loco.Session, *LoginResult, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Step 1: Booking — get checkin server address.
	booking, err := RequestBooking(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("network: booking: %w", err)
	}

	// Step 2: Checkin — get main LOCO server address.
	checkin, err := RequestCheckin(booking.CheckinHost, booking.CheckinPort, cfg, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("network: checkin: %w", err)
	}

	// Step 3: Connect to main LOCO server with encryption.
	addr := net.JoinHostPort(checkin.Host, itoa(checkin.Port))
	rawConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("network: dial main server %s: %w", addr, err)
	}

	secConn, err := loco.NewSecureConn(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("network: main server handshake: %w", err)
	}

	session := loco.NewSession(secConn)

	// Step 4: LOGINLIST — authenticate and get channel list.
	loginResult, err := sendLoginList(session, accessToken, deviceUUID, cfg)
	if err != nil {
		session.Close()
		return nil, nil, fmt.Errorf("network: login: %w", err)
	}

	return session, loginResult, nil
}

func sendLoginList(session *loco.Session, token, deviceUUID string, cfg *Config) (*LoginResult, error) {
	resp, err := session.Request("LOGINLIST", bson.M{
		"oauthToken":  token,
		"appVer":      cfg.AppVersion,
		"prtVer":      "1",
		"os":          cfg.Agent,
		"ntype":       cfg.NetType,
		"MCCMNC":      cfg.MCCMNC,
		"lang":        cfg.Language,
		"dtype":       cfg.DeviceType,
		"duuid":       deviceUUID,
		"chatIds":     bson.A{},
		"maxIds":      bson.A{},
		"lastTokenId": int64(0),
		"lbk":         0,
		"bg":          false,
		"revision":    0,
		"rp":          nil,
	})
	if err != nil {
		return nil, err
	}

	// The actual status is in the BSON body, not the LOCO packet header.
	var parsed struct {
		Status    int32      `bson:"status"`
		ChatDatas []bson.Raw `bson:"chatDatas"`
	}
	if err := bson.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("parse LOGINLIST response: %w", err)
	}

	if parsed.Status != 0 {
		return nil, fmt.Errorf("LOGINLIST failed with status %d", parsed.Status)
	}

	return &LoginResult{
		Channels: parsed.ChatDatas,
		Raw:      resp.Body,
	}, nil
}
