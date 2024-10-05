package hash_test

import (
	"testing"

	hash "github.com/shem-org/CryptoTool/internal/hash/sha256"
)

func TestSHA256Crypto_Hash(t *testing.T) {
	sha := hash.SHA256Crypto{}

	// Test case: Hash de uma string conhecida
	data := []byte("Minha mensagem secreta")
	expectedHash := "49ea4ee36633068f0747b3dd804da51c3abafa4a7246ac197fa82a0aa6fe3ebf" // Hash esperado para a mensagem

	hashedData, err := sha.Hash(data)
	if err != nil {
		t.Fatalf("generate hash %v", err)
	}

	if hashedData != expectedHash {
		t.Errorf("expected %s, got %s", expectedHash, hashedData)
	}
}
