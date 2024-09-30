package encryption

import (
	"testing"
)

func TestEncrypt(t *testing.T) {
	key := []byte("mysecretkey12345") // Key of length 16 bytes for AES-128
	plaintext := []byte("Hello, CryptoTool!")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("Ciphertext is not longer than plaintext")
	}
}
