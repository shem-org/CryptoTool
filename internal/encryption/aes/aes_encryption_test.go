package aes

import (
	"fmt"
	"testing"
)

func TestAESCrypto(t *testing.T) {
	crypto := &AESCrypto{}

	// Subtest: Successful encryption and decryption
	t.Run("EncryptDecryptSuccess", func(t *testing.T) {
		key := make([]byte, 32) // AES-256 key (32 bytes)
		plaintext := []byte("Hello, AES encryption!")

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

	// Subtest: Fails to encrypt empty plaintext
	t.Run("EncryptEmptyPlaintext", func(t *testing.T) {
		key := make([]byte, 32) // Valid AES-256 key
		plaintext := []byte("") // Empty plaintext

		_, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatal("Expected successful encryption of empty plaintext, but got error")
		}
	})

	// Subtest: Fails to decrypt empty ciphertext (should return error instead of panicking)
	t.Run("DecryptEmptyCiphertext", func(t *testing.T) {
		key := make([]byte, 32)  // Valid AES-256 key
		ciphertext := []byte("") // Empty ciphertext

		_, err := crypto.Decrypt(ciphertext, key)
		if err == nil {
			t.Fatal("Expected error when decrypting empty ciphertext, but got none")
		}
	})

	// Subtest: Encryption with different key sizes (128, 192, 256 bits)
	t.Run("EncryptDecryptDifferentKeySizes", func(t *testing.T) {
		keySizes := []int{16, 24, 32} // AES supports 128, 192, 256-bit keys
		plaintext := []byte("Testing AES with different key sizes")

		for _, size := range keySizes {
			t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
				key := make([]byte, size)
				ciphertext, err := crypto.Encrypt(plaintext, key)
				if err != nil {
					t.Fatalf("Failed to encrypt with key size %d: %v", size, err)
				}

				decrypted, err := crypto.Decrypt(ciphertext, key)
				if err != nil {
					t.Fatalf("Failed to decrypt with key size %d: %v", size, err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Expected %s with key size %d, got %s", plaintext, size, decrypted)
				}
			})
		}
	})
}
