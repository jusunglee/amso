package network

import (
	"fmt"
	"net"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/loco"
)

// CheckinResult contains the main LOCO server address returned by checkin.
type CheckinResult struct {
	Host string
	Port int
	Raw  bson.Raw
}

// RequestCheckin connects to the checkin server with LOCO encryption and
// retrieves the main LOCO server address via the CHECKIN command.
func RequestCheckin(checkinHost string, checkinPort int, cfg *Config, userID int64) (*CheckinResult, error) {
	addr := net.JoinHostPort(checkinHost, itoa(checkinPort))
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("network: checkin dial %s: %w", addr, err)
	}

	secConn, err := loco.NewSecureConn(rawConn)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("network: checkin secure handshake: %w", err)
	}
	defer secConn.Close()

	body, err := bson.Marshal(bson.M{
		"userId": userID,
		"appVer": cfg.AppVersion,
		"ntype":  cfg.NetType,
		"MCCMNC": cfg.MCCMNC,
		"os":     cfg.Agent,
		"lang":   cfg.Language,
	})
	if err != nil {
		return nil, fmt.Errorf("network: marshal checkin request: %w", err)
	}

	pkt := &loco.Packet{
		ID:       1,
		Method:   "CHECKIN",
		DataType: loco.DataTypeBSON,
		Body:     bson.Raw(body),
	}

	if err := secConn.SendPacket(pkt); err != nil {
		return nil, fmt.Errorf("network: send checkin packet: %w", err)
	}

	resp, err := secConn.RecvPacket()
	if err != nil {
		return nil, fmt.Errorf("network: read checkin response: %w", err)
	}

	var result struct {
		Host string `bson:"host"`
		Port int    `bson:"port"`
	}
	if err := bson.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("network: parse checkin response: %w", err)
	}

	if result.Host == "" {
		return nil, fmt.Errorf("network: checkin response missing host (body: %v)", resp.Body)
	}

	return &CheckinResult{
		Host: result.Host,
		Port: result.Port,
		Raw:  resp.Body,
	}, nil
}
