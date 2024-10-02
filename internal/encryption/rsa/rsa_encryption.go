package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

type RSACrypto struct{}

// Encrypt encrypts the given plaintext using the provided RSA public key.
func (r *RSACrypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	pubKey, ok := key.(*rsa.PublicKey) // Type assertion
	if !ok {
		return nil, errors.New("invalid public key type for RSA")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using the provided RSA private key.
func (r *RSACrypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	privKey, ok := key.(*rsa.PrivateKey) // Type assertion
	if !ok {
		return nil, errors.New("invalid private key type for RSA")
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	return plaintext, nil
}

// GenerateRSAKeys generates a new pair of RSA keys (public and private).
func GenerateRSAKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	if bits < 2048 {
		return nil, nil, errors.New("key size is too small; must be at least 2048 bits")
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &privKey.PublicKey
	return privKey, pubKey, nil
}
