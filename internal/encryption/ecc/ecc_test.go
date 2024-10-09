package ecc_test

import (
	"crypto/elliptic"
	"testing"

	"github.com/shem-org/CryptoTool/internal/encryption/ecc"
)

func TestECCEncryptionAndSigning(t *testing.T) {
	crypto := &ecc.ECCCrypto{}
	privKey, pubKey, err := ecc.GenerateECCKeys(elliptic.P256())
	if err != nil {
		t.Fatalf("failed to generate ECC keys: %v", err)
	}

	data := []byte("test data")
	signature, err := crypto.Sign(data, privKey)
	if err != nil {
		t.Fatalf("failed to sign data: %v", err)
	}

	valid, err := crypto.Verify(data, signature, pubKey)
	if err != nil {
		t.Fatalf("failed to verify signature: %v", err)
	}

	if !valid {
		t.Fatal("signature verification failed")
	}
}
