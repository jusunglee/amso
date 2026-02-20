// Package loco implements the LOCO wire protocol used by KakaoTalk.
package loco

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	// HeaderSize is the fixed size of a LOCO packet header.
	HeaderSize = 22
	// MethodSize is the fixed byte length of the method field (null-padded ASCII).
	MethodSize = 11
	// DataTypeBSON is the data type value for BSON payloads.
	DataTypeBSON uint8 = 0
)

// Packet represents a single LOCO protocol packet.
type Packet struct {
	ID         uint32
	StatusCode uint16
	Method     string
	DataType   uint8
	Body       bson.Raw
}

// EncodePacket serializes a Packet into bytes (header + BSON body).
func EncodePacket(p *Packet) ([]byte, error) {
	bodyBytes := []byte(p.Body)
	if bodyBytes == nil {
		// Empty BSON document.
		var err error
		bodyBytes, err = bson.Marshal(bson.M{})
		if err != nil {
			return nil, fmt.Errorf("loco: marshal empty body: %w", err)
		}
	}

	buf := make([]byte, HeaderSize+len(bodyBytes))

	// ID: uint32 LE [0:4]
	binary.LittleEndian.PutUint32(buf[0:4], p.ID)
	// StatusCode: uint16 LE [4:6]
	binary.LittleEndian.PutUint16(buf[4:6], p.StatusCode)
	// Method: 11 bytes null-padded ASCII [6:17]
	copy(buf[6:17], methodToBytes(p.Method))
	// DataType: uint8 [17]
	buf[17] = p.DataType
	// DataSize: uint32 LE [18:22]
	binary.LittleEndian.PutUint32(buf[18:22], uint32(len(bodyBytes)))
	// Body
	copy(buf[HeaderSize:], bodyBytes)

	return buf, nil
}

// DecodePacket reads a single LOCO packet from the reader.
func DecodePacket(r io.Reader) (*Packet, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("loco: read header: %w", err)
	}

	p := &Packet{
		ID:         binary.LittleEndian.Uint32(header[0:4]),
		StatusCode: binary.LittleEndian.Uint16(header[4:6]),
		Method:     bytesToMethod(header[6:17]),
		DataType:   header[17],
	}

	dataSize := binary.LittleEndian.Uint32(header[18:22])
	if dataSize > 0 {
		body := make([]byte, dataSize)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("loco: read body (%d bytes): %w", dataSize, err)
		}
		p.Body = bson.Raw(body)
	}

	return p, nil
}

func methodToBytes(m string) []byte {
	b := make([]byte, MethodSize)
	copy(b, []byte(m))
	return b
}

func bytesToMethod(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}
