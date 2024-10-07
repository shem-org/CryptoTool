package blowfish_test

import (
	"testing"

	"github.com/shem-org/CryptoTool/internal/encryption/blowfish"
)

func TestBlowfishEncryptDecrypt(t *testing.T) {
	crypto := &blowfish.BlowfishCrypto{}
	key := []byte("examplekey12345") // Key size pode variar com Blowfish

	plaintext := []byte("test data")
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("expected %s but got %s", plaintext, decrypted)
	}
}
