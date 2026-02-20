package loco

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jusunglee/amso/crypto"
)

const (
	// Handshake constants from KakaoTalk APK v26.1.3 (kq/d.java SecureLayer).
	rsaTypeOAEPSHA1 uint32 = 16
	aesTypeCFB128   uint32 = 2
)

// SecureConn wraps a raw TCP connection with LOCO's encryption layer.
// After handshake, all reads and writes are AES-128-CFB encrypted.
type SecureConn struct {
	conn   net.Conn
	aesKey []byte
	mu     sync.Mutex // serializes writes
}

// NewSecureConn creates a new SecureConn by generating an AES key, encrypting it
// with the LOCO RSA public key, and sending the handshake to the server.
func NewSecureConn(conn net.Conn) (*SecureConn, error) {
	aesKey, err := crypto.GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("loco: generate AES key: %w", err)
	}

	encKey, err := crypto.EncryptAESKey(aesKey)
	if err != nil {
		return nil, fmt.Errorf("loco: encrypt AES key: %w", err)
	}

	// Handshake: [encrypted_key_len:u32LE][rsaType:u32LE][aesType:u32LE][encrypted_key]
	handshake := make([]byte, 12+len(encKey))
	binary.LittleEndian.PutUint32(handshake[0:4], uint32(len(encKey)))
	binary.LittleEndian.PutUint32(handshake[4:8], rsaTypeOAEPSHA1)
	binary.LittleEndian.PutUint32(handshake[8:12], aesTypeCFB128)
	copy(handshake[12:], encKey)

	if _, err := conn.Write(handshake); err != nil {
		return nil, fmt.Errorf("loco: write handshake: %w", err)
	}

	return &SecureConn{conn: conn, aesKey: aesKey}, nil
}

// WritePacket encrypts and writes raw data.
// Format: [total_size:u32LE][16-byte IV][AES-CFB encrypted data]
func (sc *SecureConn) WritePacket(data []byte) error {
	iv, ciphertext, err := crypto.AESEncrypt(sc.aesKey, data)
	if err != nil {
		return fmt.Errorf("loco: encrypt: %w", err)
	}

	totalSize := uint32(len(iv) + len(ciphertext))
	header := make([]byte, 4)
	binary.LittleEndian.PutUint32(header, totalSize)

	// Combine into a single write to avoid TCP fragmentation issues.
	buf := make([]byte, 4+len(iv)+len(ciphertext))
	copy(buf[0:4], header)
	copy(buf[4:4+len(iv)], iv)
	copy(buf[4+len(iv):], ciphertext)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, err := sc.conn.Write(buf); err != nil {
		return fmt.Errorf("loco: write packet: %w", err)
	}
	return nil
}

// ReadPacket reads and decrypts a single encrypted packet.
// Format: [total_size:u32LE][16-byte IV][AES-CFB encrypted data]
func (sc *SecureConn) ReadPacket() ([]byte, error) {
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(sc.conn, sizeBuf); err != nil {
		return nil, fmt.Errorf("loco: read size: %w", err)
	}
	totalSize := binary.LittleEndian.Uint32(sizeBuf)

	if totalSize < uint32(aes.BlockSize) {
		return nil, fmt.Errorf("loco: encrypted packet too small: %d", totalSize)
	}

	payload := make([]byte, totalSize)
	if _, err := io.ReadFull(sc.conn, payload); err != nil {
		return nil, fmt.Errorf("loco: read payload: %w", err)
	}

	iv := payload[:aes.BlockSize]
	ciphertext := payload[aes.BlockSize:]

	plaintext, err := crypto.AESDecrypt(sc.aesKey, iv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("loco: decrypt: %w", err)
	}
	return plaintext, nil
}

// SendPacket encodes a LOCO Packet and writes it encrypted.
func (sc *SecureConn) SendPacket(p *Packet) error {
	data, err := EncodePacket(p)
	if err != nil {
		return err
	}
	return sc.WritePacket(data)
}

// RecvPacket reads and decrypts a LOCO Packet.
func (sc *SecureConn) RecvPacket() (*Packet, error) {
	data, err := sc.ReadPacket()
	if err != nil {
		return nil, err
	}
	return DecodePacket(newByteReader(data))
}

// Close closes the underlying connection.
func (sc *SecureConn) Close() error {
	return sc.conn.Close()
}

// newByteReader returns an io.Reader over a byte slice. This avoids importing bytes
// just for bytes.NewReader in this package.
func newByteReader(b []byte) io.Reader {
	return &byteReader{data: b}
}

type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// GenerateIV produces a random 16-byte initialization vector. Exposed for testing.
func GenerateIV() ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}
