package hash

import (
	"crypto/sha256"
	"fmt"
)

type SHA256Crypto struct{}

// Hash generates the SHA-256 hash for the given data.
func (s *SHA256Crypto) Hash(data []byte) (string, error) {
	hash := sha256.New()
	hash.Write(data)
	hashedData := fmt.Sprintf("%x", hash.Sum(nil))
	return hashedData, nil
}
