package triple_des

import (
	"bytes"
	"testing"
)

// TestTripleDESCrypto_EncryptDecrypt tests the Encrypt and Decrypt methods of TripleDESCrypto.
func TestTripleDESCrypto_EncryptDecrypt(t *testing.T) {
	// Define a valid 24-byte key for 3DES encryption
	key := []byte("123456789012345678901234") // 24 bytes (3 * 8)

	// Define the plaintext to be encrypted
	plaintext := []byte("This is a secret message")

	// Create a new instance of TripleDESCrypto
	crypto := &TripleDESCrypto{}

	// Test encryption
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Test decryption
	decryptedText, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	// Verify that the decrypted text matches the original plaintext
	if !bytes.Equal(plaintext, decryptedText) {
		t.Errorf("Decrypt() mismatch: expected %s, got %s", plaintext, decryptedText)
	}
}

// TestTripleDESCrypto_InvalidKey tests encryption and decryption with an invalid key.
func TestTripleDESCrypto_InvalidKey(t *testing.T) {
	// Define an invalid key (not 24 bytes)
	invalidKey := []byte("shortkey")

	// Define the plaintext to be encrypted
	plaintext := []byte("This is a secret message")

	// Create a new instance of TripleDESCrypto
	crypto := &TripleDESCrypto{}

	// Test encryption with an invalid key
	_, err := crypto.Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Fatalf("Encrypt() expected error with invalid key, got nil")
	}

	// Test decryption with an invalid key
	_, err = crypto.Decrypt(plaintext, invalidKey)
	if err == nil {
		t.Fatalf("Decrypt() expected error with invalid key, got nil")
	}
}

// TestTripleDESCrypto_InvalidDataType tests encryption and decryption with an invalid data type for the key.
func TestTripleDESCrypto_InvalidDataType(t *testing.T) {
	// Define a key of invalid type (not []byte)
	invalidKey := "this is a string, not a []byte"

	// Define the plaintext to be encrypted
	plaintext := []byte("This is a secret message")

	// Create a new instance of TripleDESCrypto
	crypto := &TripleDESCrypto{}

	// Test encryption with an invalid key type
	_, err := crypto.Encrypt(plaintext, invalidKey)
	if err == nil {
		t.Fatalf("Encrypt() expected error with invalid key type, got nil")
	}

	// Test decryption with an invalid key type
	_, err = crypto.Decrypt(plaintext, invalidKey)
	if err == nil {
		t.Fatalf("Decrypt() expected error with invalid key type, got nil")
	}
}
