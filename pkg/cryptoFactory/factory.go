package cryptoFactory

import (
	"errors"

	"github.com/BliShem/CryptoTool/internal/encryption/aes"
	"github.com/BliShem/CryptoTool/internal/encryption/rsa"
	"github.com/BliShem/CryptoTool/internal/interfaces"
)

const (
	AES = "AES"
	RSA = "RSA"
)

func GetCrypto(algo string) (interfaces.Crypto, error) {
	switch algo {
	case AES:
		return &aes.AESCrypto{}, nil
	case RSA:
		crypto := &rsa.RSACrypto{}
		err := crypto.GenerateKeys(2048) // RSA key generator (2048 bits)
		if err != nil {
			return nil, err
		}
		return crypto, nil
	default:
		return nil, errors.New("unsupported algorithm")
	}
}
