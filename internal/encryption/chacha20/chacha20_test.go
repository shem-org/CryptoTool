package chacha20_test

import (
	"testing"

	"github.com/shem-org/CryptoTool/internal/encryption/chacha20"
)

func TestChaCha20Crypto(t *testing.T) {
	crypto := &chacha20.ChaCha20Crypto{}

	// Subtest: Successful encryption and decryption
	t.Run("EncryptDecryptSuccess", func(t *testing.T) {
		key := make([]byte, 32) // 256-bit key for ChaCha20 (32 bytes)
		plaintext := []byte("Hello, ChaCha20 encryption!")

		// Encrypt
		ciphertext, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt
		decrypted, err := crypto.Decrypt(ciphertext, key)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Fatalf("Expected %s, got %s", plaintext, decrypted)
		}
	})

	// Subtest: Fails to encrypt with an invalid key length
	t.Run("EncryptInvalidKeyLength", func(t *testing.T) {
		key := make([]byte, 16) // Invalid key length for ChaCha20 (should be 32 bytes)
		plaintext := []byte("This is a test message")

		_, err := crypto.Encrypt(plaintext, key)
		if err == nil {
			t.Fatal("Expected error for invalid key length, but got none")
		} else {
			t.Logf("Correctly failed to encrypt with invalid key length: %v", err)
		}
	})

	// Subtest: Fails to decrypt with an invalid key
	t.Run("DecryptInvalidKey", func(t *testing.T) {
		key := make([]byte, 32)                                       // Valid 256-bit key for ChaCha20
		invalidKey := []byte("this-is-an-invalid-key-12345678901234") // Invalid key for decryption
		plaintext := []byte("This is a test message")

		// Encrypt the plaintext
		ciphertext, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Attempt to decrypt with an invalid key
		_, err = crypto.Decrypt(ciphertext, invalidKey)
		if err == nil {
			t.Fatal("Expected error for invalid key during decryption, but got none")
		} else {
			t.Logf("Correctly failed to decrypt with invalid key: %v", err)
		}
	})

	// Subtest: Fails to decrypt with invalid ciphertext
	t.Run("DecryptInvalidCiphertext", func(t *testing.T) {
		key := make([]byte, 32) // Valid 256-bit key for ChaCha20
		invalidCiphertext := []byte("invalid-ciphertext")

		_, err := crypto.Decrypt(invalidCiphertext, key)
		if err == nil {
			t.Fatal("Expected error for invalid ciphertext, but got none")
		} else {
			t.Logf("Correctly failed to decrypt with invalid ciphertext: %v", err)
		}
	})
}
