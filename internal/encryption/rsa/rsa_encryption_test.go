package rsa

import (
	"fmt"
	"testing"
)

func TestRSACrypto(t *testing.T) {
	// Generate RSA keys
	privKey, pubKey, err := GenerateRSAKeys(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	crypto := &RSACrypto{}

	// Subtest: Successful encryption and decryption
	t.Run("EncryptDecryptSuccess", func(t *testing.T) {
		plaintext := []byte("Hello, RSA encryption!")

		// Encrypt
		ciphertext, err := crypto.Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Decrypt
		decrypted, err := crypto.Decrypt(ciphertext, privKey)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Fatalf("Expected %s, got %s", plaintext, decrypted)
		}
	})

	// Subtest: Fails with invalid public key
	t.Run("InvalidPublicKey", func(t *testing.T) {
		plaintext := []byte("This should fail")
		invalidPubKey := "invalid public key" // Invalid key type

		_, err := crypto.Encrypt(plaintext, invalidPubKey)
		if err == nil {
			t.Fatal("Expected error when using an invalid public key, but got none")
		}
	})

	// Subtest: Fails to decrypt with invalid private key
	t.Run("InvalidPrivateKey", func(t *testing.T) {
		plaintext := []byte("Hello, RSA encryption!")

		// Encrypt
		ciphertext, err := crypto.Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		invalidPrivKey := "invalid private key" // Invalid key type

		// Attempt to decrypt with invalid private key
		_, err = crypto.Decrypt(ciphertext, invalidPrivKey)
		if err == nil {
			t.Fatal("Expected error when using an invalid private key, but got none")
		}
	})

	// Subtest: Fails to decrypt with wrong private key
	t.Run("DecryptWithWrongPrivateKey", func(t *testing.T) {
		// Generate a new pair of RSA keys for a wrong private key
		wrongPrivKey, _, err := GenerateRSAKeys(2048)
		if err != nil {
			t.Fatalf("Failed to generate wrong RSA key: %v", err)
		}

		plaintext := []byte("Hello, RSA encryption!")

		// Encrypt
		ciphertext, err := crypto.Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		// Attempt to decrypt with wrong private key
		_, err = crypto.Decrypt(ciphertext, wrongPrivKey)
		if err == nil {
			t.Fatal("Expected error when decrypting with wrong private key, but got none")
		}
	})

	// Subtest: Fails to encrypt empty plaintext
	t.Run("EncryptEmptyPlaintext", func(t *testing.T) {
		plaintext := []byte("") // Empty plaintext

		_, err := crypto.Encrypt(plaintext, pubKey)
		if err != nil {
			t.Fatal("Expected successful encryption of empty plaintext, but got error")
		}
	})

	// Subtest: Fails to decrypt empty ciphertext
	t.Run("DecryptEmptyCiphertext", func(t *testing.T) {
		ciphertext := []byte("") // Empty ciphertext

		_, err := crypto.Decrypt(ciphertext, privKey)
		if err == nil {
			t.Fatal("Expected error when decrypting empty ciphertext, but got none")
		}
	})

	// Subtest: Encryption and decryption with different key sizes (2048, 4096 bits)
	t.Run("EncryptDecryptDifferentKeySizes", func(t *testing.T) {
		keySizes := []int{2048, 4096}
		plaintext := []byte("Testing RSA with different key sizes")

		for _, size := range keySizes {
			t.Run(fmt.Sprintf("%d", size), func(t *testing.T) { // Correção do erro
				privKey, pubKey, err := GenerateRSAKeys(size)
				if err != nil {
					t.Fatalf("Failed to generate RSA keys with size %d: %v", size, err)
				}

				ciphertext, err := crypto.Encrypt(plaintext, pubKey)
				if err != nil {
					t.Fatalf("Failed to encrypt with key size %d: %v", size, err)
				}

				decrypted, err := crypto.Decrypt(ciphertext, privKey)
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
