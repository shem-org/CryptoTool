package cryptoFactory

import (
	"errors"

	"github.com/BliShem/CryptoTool/internal/encryption/aes"
	"github.com/BliShem/CryptoTool/internal/interfaces"
)

const (
	AES = "AES"
)

func GetCrypto(algo string) (interfaces.Crypto, error) {
	switch algo {
	case AES:
		return &aes.AESCrypto{}, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}
