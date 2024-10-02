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
