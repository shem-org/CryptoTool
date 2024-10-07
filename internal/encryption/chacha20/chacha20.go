package chacha20

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/shem-org/CryptoTool/internal/interfaces"
)

var _ interfaces.Crypto = (*ChaCha20Crypto)(nil)

// ChaCha20Crypto implements the Crypto interface for ChaCha20
type ChaCha20Crypto struct{}

// Encrypt performs encryption using ChaCha20-Poly1305 with a 256-bit key
func (c *ChaCha20Crypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes for ChaCha20-Poly1305", chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext using Seal (AEAD encryption)
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt performs decryption using ChaCha20-Poly1305 with a 256-bit key
func (c *ChaCha20Crypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes for ChaCha20-Poly1305", chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.New(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20-Poly1305 cipher: %w", err)
	}

	if len(ciphertext) < chacha20poly1305.NonceSize {
		return nil, errors.New("ciphertext is too short")
	}

	nonce, ciphertext := ciphertext[:chacha20poly1305.NonceSize], ciphertext[chacha20poly1305.NonceSize:]

	// Decrypt the ciphertext using Open
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
