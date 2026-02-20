// Package network implements the KakaoTalk LOCO connection flow: booking → checkin → main session.
package network

import (
	"crypto/tls"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/jusunglee/amso/loco"
)

const (
	BookingHost = "booking-loco.kakao.com"
	BookingPort = 443
)

// BookingConfig contains server configuration returned by the booking server.
type BookingConfig struct {
	CheckinHost string
	CheckinPort int

	// Raw response fields for any additional data.
	Raw bson.Raw
}

// RequestBooking connects to the booking server over TLS and retrieves
// server configuration via the GETCONF LOCO command.
func RequestBooking(cfg *Config) (*BookingConfig, error) {
	host := BookingHost
	port := BookingPort

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{})
	if err != nil {
		return nil, fmt.Errorf("network: booking TLS dial: %w", err)
	}
	defer conn.Close()

	// Booking uses plain (non-encrypted) LOCO over TLS.
	body, err := bson.Marshal(bson.M{
		"MCCMNC": cfg.MCCMNC,
		"model":  cfg.DeviceModel,
		"os":     cfg.Agent,
		"ntype":  cfg.NetType,
		"appVer": cfg.AppVersion,
		"lang":   cfg.Language,
	})
	if err != nil {
		return nil, fmt.Errorf("network: marshal booking request: %w", err)
	}

	pkt := &loco.Packet{
		ID:       1,
		Method:   "GETCONF",
		DataType: loco.DataTypeBSON,
		Body:     bson.Raw(body),
	}

	encoded, err := loco.EncodePacket(pkt)
	if err != nil {
		return nil, fmt.Errorf("network: encode booking packet: %w", err)
	}

	if _, err := conn.Write(encoded); err != nil {
		return nil, fmt.Errorf("network: write booking packet: %w", err)
	}

	resp, err := loco.DecodePacket(conn)
	if err != nil {
		return nil, fmt.Errorf("network: read booking response: %w", err)
	}

	var result struct {
		Host string `bson:"host"`
		Port int    `bson:"port"`
		// ticket.lsl is an array of checkin server hosts.
		Ticket struct {
			Hosts []string `bson:"lsl"`
		} `bson:"ticket"`
		// wifi.ports has the ports for LOCO connections.
		Wifi struct {
			Ports []int `bson:"ports"`
		} `bson:"wifi"`
	}
	if err := bson.Unmarshal(resp.Body, &result); err != nil {
		return nil, fmt.Errorf("network: parse booking response: %w", err)
	}

	bcfg := &BookingConfig{
		CheckinHost: result.Host,
		CheckinPort: result.Port,
		Raw:         resp.Body,
	}

	// Use ticket.lsl hosts and wifi.ports if direct fields are empty.
	if bcfg.CheckinHost == "" && len(result.Ticket.Hosts) > 0 {
		bcfg.CheckinHost = result.Ticket.Hosts[0]
	}
	if bcfg.CheckinPort == 0 && len(result.Wifi.Ports) > 0 {
		bcfg.CheckinPort = result.Wifi.Ports[0]
	}

	if bcfg.CheckinHost == "" {
		return nil, fmt.Errorf("network: booking response missing checkin host (body: %v)", resp.Body)
	}

	return bcfg, nil
}
