// Package crypto provides AES-128-CFB and RSA OAEP primitives for the LOCO protocol.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"io"
	"math/big"
)

// locoRSAModulus is the RSA modulus from KakaoTalk Android APK v26.1.3
// (kq/d.java SecureLayer, RSAPublicKeySpec).
const locoRSAModulus = "A3B076E8C445851F19A670C231AAC6DB42EFD09717D06048A5CC56906CD1AB27B9DF37FFD5017E7C13A1405B5D1C3E4879A6A499D3C618A72472B0B50CA5EF1EF6EEA70369D9413FE662D8E2B479A9F72142EE70CEE6C2AD12045D52B25C4A204A28968E37F0BA6A49EE3EC9F2AC7A65184160F22F62C43A4067CD8D2A6F13D9B8298AB002763D236C9D1879D7FCE5B8FA910882B21E15247E0D0A24791308E51983614402E9FA03057C57E9E178B1CC39FE67288EFC461945CBCAA11D1FCC123E750B861F0D447EBE3C115F411A42DC95DDB21DA42774A5BCB1DDF7FA5F10628010C74F36F31C40EFCFE289FD81BABA44A6556A6C301210414B6023C3F46371"

var locoRSAKey *rsa.PublicKey

func init() {
	n := new(big.Int)
	n.SetString(locoRSAModulus, 16)
	locoRSAKey = &rsa.PublicKey{
		N: n,
		E: 3,
	}
}

// GenerateAESKey returns a random 16-byte key for AES-128.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAESKey encrypts a 16-byte AES key with the LOCO RSA public key using RSA-OAEP-SHA1.
func EncryptAESKey(aesKey []byte) ([]byte, error) {
	if len(aesKey) != 16 {
		return nil, errors.New("crypto: AES key must be 16 bytes")
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, locoRSAKey, aesKey, nil)
}

// AESEncrypt encrypts plaintext with AES-128-CFB using the given key. Returns a random IV and ciphertext.
func AESEncrypt(key, plaintext []byte) (iv, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	ciphertext = make([]byte, len(plaintext))
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)
	return iv, ciphertext, nil
}

// AESDecrypt decrypts ciphertext with AES-128-CFB using the given key and IV.
func AESDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
