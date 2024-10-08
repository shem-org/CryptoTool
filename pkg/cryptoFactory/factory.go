package cryptoFactory

import (
	"errors"

	"github.com/shem-org/CryptoTool/internal/encryption/aes"
	"github.com/shem-org/CryptoTool/internal/encryption/blowfish"
	"github.com/shem-org/CryptoTool/internal/encryption/chacha20"
	"github.com/shem-org/CryptoTool/internal/encryption/des"
	"github.com/shem-org/CryptoTool/internal/encryption/rsa"
<<<<<<< HEAD
	"github.com/shem-org/CryptoTool/internal/hash"
=======
	"github.com/shem-org/CryptoTool/internal/encryption/triple_des"
	"github.com/shem-org/CryptoTool/internal/hash/hmac"
	hash "github.com/shem-org/CryptoTool/internal/hash/sha256"

	"github.com/shem-org/CryptoTool/internal/interfaces"
)

const (
	AES        = "AES"
	RSA        = "RSA"
	SHA256     = "SHA256"
	SHA3       = "SHA3-256"
	TripleDES  = "3DES"
	DES        = "DES"
	ChaCha20   = "ChaCha20"
	Blowfish   = "Blowfish"
	HMACSHA256 = "HMAC-SHA256"
	HMACSHA3   = "HMAC-SHA3-256"
)

func GetCrypto(algo string, bits int) (interfaces.Crypto, interface{}, interface{}, error) {
	switch algo {
	case AES:
		key := make([]byte, 32) // Example key for AES-256
		return &aes.AESCrypto{}, key, nil, nil
	case RSA:
		privKey, pubKey, err := rsa.GenerateRSAKeys(bits)
		if err != nil {
			return nil, nil, nil, err
		}
		return &rsa.RSACrypto{}, privKey, pubKey, nil
	case TripleDES:
		key := make([]byte, 24) // Example key for 3DES (24 bytes)
		return &triple_des.TripleDESCrypto{}, key, nil, nil
	case DES:
		key := make([]byte, 8) // Example key for DES (8 bytes)
		return &des.DESCrypto{}, key, nil, nil
	case ChaCha20:
		key := make([]byte, 32) // Key size for ChaCha20 is 256 bits (32 bytes)
		return &chacha20.ChaCha20Crypto{}, key, nil, nil
	case Blowfish:
		key := make([]byte, 16) // Example key size for Blowfish
		return &blowfish.BlowfishCrypto{}, key, nil, nil
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

// New function for HMAC
func GetHMACFunction(algo string) (interfaces.HMAC, error) {
	switch algo {
	case HMACSHA256:
		return hmac.NewHMAC("SHA256")
	case HMACSHA3:
		return hmac.NewHMAC("SHA3-256")
	default:
		return nil, errors.New("unsupported HMAC algorithm")
	}
}
