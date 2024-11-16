package scrypt_test

import (
	"testing"

	"github.com/shem-org/CryptoTool/internal/hash/scrypt"
)

func TestScryptHashing(t *testing.T) {
	password := []byte("supersecret")

	scryptCrypto := &scrypt.ScryptCrypto{}

	// Hash the password
	hashedPassword, err := scryptCrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	// Compare the hashed password with the original password
	match, err := scryptCrypto.CompareHashAndPassword(hashedPassword, password)
	if err != nil || !match {
		t.Fatalf("Password comparison failed")
	}
}
