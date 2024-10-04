package cryptoFactory

import (
	"errors"

	"github.com/shem-org/CryptoTool/internal/encryption/aes"
	"github.com/shem-org/CryptoTool/internal/encryption/rsa"
	hash "github.com/shem-org/CryptoTool/internal/hash/sha256"
	"github.com/shem-org/CryptoTool/internal/interfaces"
)

const (
	AES    = "AES"
	RSA    = "RSA"
	SHA256 = "SHA256"
)

func GetCrypto(algo string, bits int) (interfaces.Crypto, interface{}, interface{}, error) {
	switch algo {
	case AES:
		key := make([]byte, 32) // exemple key AES-256
		return &aes.AESCrypto{}, key, nil, nil
	case RSA:
		// Generates and returns the RSA instance, private key and public key
		privKey, pubKey, err := rsa.GenerateRSAKeys(bits)
		if err != nil {
			return nil, nil, nil, err
		}
		return &rsa.RSACrypto{}, privKey, pubKey, nil
	default:
		return nil, nil, nil, errors.New("unsupported algorithm")
	}
}

func GetHashFunction(algo string) (interfaces.Hash, error) {
	switch algo {
	case SHA256:
		return &hash.SHA256Crypto{}, nil
	default:
		return nil, errors.New("unsupported hash algorithm")
	}
}
