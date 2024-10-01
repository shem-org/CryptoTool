package encryption

import (
	"fmt"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	key := []byte("mysecretkey12345") // Key of length 16 bytes for AES-128
	plaintext := []byte("Hello, CryptoTool!")

	// Test encryption
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if len(ciphertext) <= len(plaintext) {
		t.Fatalf("Ciphertext is not longer than plaintext")
	}

	// Test decryption
	// TODO: uncomment this block after implementing decryption
	// decryptedText, err := Decrypt(ciphertext, key)
	// if err != nil {
	// 	t.Fatalf("Failed to decrypt: %v", err)
	// }

	// Compare decrypted text with original plaintext
	// if !bytes.Equal(decryptedText, plaintext) {
	// 	t.Fatalf("Decrypted text does not match original plaintext. Got %s, expected %s", decryptedText, plaintext)
	// }
}

func TestInvalidKeyLength(t *testing.T) {
	key := []byte("shortkey") // Invalid key length
	plaintext := []byte("Hello, CryptoTool!")

	_, err := Encrypt(plaintext, key)
	if err == nil {
		t.Fatal("Expected an error due to invalid key length, but got nil")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	key := []byte("mysecretkey12345") // Valid key length
	plaintext := []byte("")

	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	fmt.Println(ciphertext) // remove this line after decryption is implemented

	// Test decryption with empty plaintext
	// decryptedText, err := Decrypt(ciphertext, key)
	// if err != nil {
	// 	t.Fatalf("Failed to decrypt: %v", err)
	// }

	// if !bytes.Equal(decryptedText, plaintext) {
	// 	t.Fatalf("Decrypted text does not match original empty plaintext")
	// }
}
