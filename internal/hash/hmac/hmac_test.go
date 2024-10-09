package hmac_test

import (
	"testing"

	"github.com/shem-org/CryptoTool/internal/hash/hmac"
)

func TestHMACSHA256(t *testing.T) {
	key := []byte("supersecretkey")
	data := []byte("important data")

	hmacCrypto, err := hmac.NewHMAC("SHA256")
	if err != nil {
		t.Fatalf("Failed to create HMAC: %v", err)
	}

	generatedHMAC, err := hmacCrypto.GenerateHMAC(data, key)
	if err != nil {
		t.Fatalf("Failed to generate HMAC: %v", err)
	}

	isValid, err := hmacCrypto.VerifyHMAC(data, key, generatedHMAC)
	if err != nil || !isValid {
		t.Fatalf("HMAC verification failed")
	}
}

func TestHMACSHA3(t *testing.T) {
	key := []byte("anothersecretkey")
	data := []byte("different data")

	hmacCrypto, err := hmac.NewHMAC("SHA3-256")
	if err != nil {
		t.Fatalf("Failed to create HMAC: %v", err)
	}

	generatedHMAC, err := hmacCrypto.GenerateHMAC(data, key)
	if err != nil {
		t.Fatalf("Failed to generate HMAC: %v", err)
	}

	isValid, err := hmacCrypto.VerifyHMAC(data, key, generatedHMAC)
	if err != nil || !isValid {
		t.Fatalf("HMAC verification failed")
	}
}
