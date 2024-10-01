package aes_test

import (
	"bytes"
	"testing"

	"github.com/BliShem/CryptoTool/pkg/cryptoFactory"
)

func TestAESCrypto(t *testing.T) {
	key := []byte("mysecretkey12345") // 16 bytes key for AES-128
	plaintext := []byte("Hello, CryptoTool!")

	// Retrieve the AES algorithm from the factory
	crypto, err := cryptoFactory.GetCrypto(cryptoFactory.AES)
	if err != nil {
		t.Fatalf("Failed to get AES implementation: %v", err)
	}

	// Test encryption
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Ensure the ciphertext is longer than the plaintext
	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("Ciphertext should be longer than plaintext")
	}

	// Test decryption
	decryptedText, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Compare the original text with the decrypted text
	if !bytes.Equal(decryptedText, plaintext) {
		t.Fatalf("Decrypted text does not match the original. Got: %s, Expected: %s", decryptedText, plaintext)
	}
}
