package des

import (
	"fmt"
	"testing"
)

func TestDESCrypto(t *testing.T) {
	crypto := &DESCrypto{}

	// Subtest: Successful encryption and decryption
	t.Run("EncryptDecryptSuccess", func(t *testing.T) {
		key := []byte("1234567") // 56-bit DES key (7 bytes)
		plaintext := []byte("Hello, DES encryption!")

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
		key := []byte("123456") // Invalid key (6 bytes)
		plaintext := []byte("This is a test message")

		_, err := crypto.Encrypt(plaintext, key)
		if err == nil {
			t.Fatal("Expected error for invalid key length, but got none")
		}
	})

	// Subtest: Fails to decrypt with an invalid key
	t.Run("DecryptInvalidKey", func(t *testing.T) {
		key := []byte("1234567")        // 7-byte valid key for DES
		invalidKey := []byte("7654321") // Different key for decryption
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

	// Subtest: Handles empty plaintext encryption
	t.Run("EncryptEmptyPlaintext", func(t *testing.T) {
		key := []byte("1234567") // Valid 7-byte key for DES
		plaintext := []byte("")  // Empty plaintext

		_, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			t.Fatal("Expected successful encryption of empty plaintext, but got error")
		}
	})

	// Subtest: Fails to decrypt empty ciphertext (should return error)
	t.Run("DecryptEmptyCiphertext", func(t *testing.T) {
		key := []byte("1234567") // Valid 7-byte key for DES
		ciphertext := []byte("") // Empty ciphertext

		_, err := crypto.Decrypt(ciphertext, key)
		if err == nil {
			t.Fatal("Expected error when decrypting empty ciphertext, but got none")
		}
	})

	// Subtest: Encryption and decryption with various plaintext lengths
	t.Run("EncryptDecryptVariousPlaintextLengths", func(t *testing.T) {
		key := []byte("1234567") // 7-byte valid key for DES
		plaintexts := []string{
			"Short", // Short message
			"This is a message with exactly 64 bytes. Let's ensure it works with this.", // Exactly 64 bytes
			"This is a longer message that spans multiple blocks in the DES cipher mode.",
		}

		for _, plaintext := range plaintexts {
			t.Run(fmt.Sprintf("%d bytes", len(plaintext)), func(t *testing.T) {
				ciphertext, err := crypto.Encrypt([]byte(plaintext), key)
				if err != nil {
					t.Fatalf("Failed to encrypt plaintext of length %d: %v", len(plaintext), err)
				}

				decrypted, err := crypto.Decrypt(ciphertext, key)
				if err != nil {
					t.Fatalf("Failed to decrypt plaintext of length %d: %v", len(plaintext), err)
				}

				if string(decrypted) != plaintext {
					t.Fatalf("Expected %s, got %s", plaintext, decrypted)
				}
			})
		}
	})
}
