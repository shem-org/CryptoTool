package scrypt

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"

	"github.com/shem-org/CryptoTool/internal/interfaces"
)

var _ interfaces.PasswordHasher = (*ScryptCrypto)(nil)

// ScryptCrypto implements the PasswordHasher interface using scrypt
type ScryptCrypto struct{}

// HashPassword generates a scrypt hash for the given password
func (s *ScryptCrypto) HashPassword(password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	hashedPassword, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	return append(salt, hashedPassword...), nil
}

// CompareHashAndPassword compares a scrypt hashed password with a plaintext password
func (s *ScryptCrypto) CompareHashAndPassword(hashedPassword, password []byte) (bool, error) {
	if len(hashedPassword) < 16 {
		return false, errors.New("invalid hash length")
	}

	salt := hashedPassword[:16]
	hash := hashedPassword[16:]

	newHash, err := scrypt.Key(password, salt, 32768, 8, 1, 32)
	if err != nil {
		return false, err
	}

	return string(newHash) == string(hash), nil
}
