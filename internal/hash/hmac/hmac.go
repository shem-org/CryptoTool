package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"

	"golang.org/x/crypto/sha3"
)

// HMACCrypto implements the HMAC interface for different hash algorithms
type HMACCrypto struct {
	hashFunc func() hash.Hash
}

// NewHMAC returns an HMACCrypto instance for the given algorithm
func NewHMAC(algo string) (*HMACCrypto, error) {
	switch algo {
	case "SHA256":
		return &HMACCrypto{hashFunc: sha256.New}, nil
	case "SHA3-256":
		return &HMACCrypto{hashFunc: sha3.New256}, nil
	default:
		return nil, errors.New("unsupported hash algorithm")
	}
}

// GenerateHMAC generates an HMAC for the given data using the provided key
func (h *HMACCrypto) GenerateHMAC(data, key []byte) ([]byte, error) {
	mac := hmac.New(h.hashFunc, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// VerifyHMAC verifies that the given HMAC matches the generated HMAC for the data
func (h *HMACCrypto) VerifyHMAC(data, key, hmacValue []byte) (bool, error) {
	generatedHMAC, err := h.GenerateHMAC(data, key)
	if err != nil {
		return false, err
	}
	return hmac.Equal(hmacValue, generatedHMAC), nil
}
