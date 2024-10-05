package cryptoFactory

import (
	"errors"

	"github.com/shem-org/CryptoTool/internal/encryption/aes"
	"github.com/shem-org/CryptoTool/internal/encryption/rsa"
<<<<<<< HEAD
	"github.com/shem-org/CryptoTool/internal/hash"
=======
	"github.com/shem-org/CryptoTool/internal/encryption/triple_des"
	hash "github.com/shem-org/CryptoTool/internal/hash/sha256"
>>>>>>> d57b274 (feat: implement 3DES encryption and decryption using CBC mode)
	"github.com/shem-org/CryptoTool/internal/interfaces"
)

const (
	AES       = "AES"
	RSA       = "RSA"
	SHA256    = "SHA256"
	TripleDES = "3DES"
)

func GetCrypto(algo string, bits int) (interfaces.Crypto, interface{}, interface{}, error) {
	switch algo {
	case AES:
		key := make([]byte, 32) // Example key for AES-256
		return &aes.AESCrypto{}, key, nil, nil
	case RSA:
		// Generate and return RSA keys (private and public)
		privKey, pubKey, err := rsa.GenerateRSAKeys(bits)
		if err != nil {
			return nil, nil, nil, err
		}
		return &rsa.RSACrypto{}, privKey, pubKey, nil
	case TripleDES:
		key := make([]byte, 24) // Example key for 3DES (24 bytes)
		return &triple_des.TripleDESCrypto{}, key, nil, nil
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
