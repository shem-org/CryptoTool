package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

type RSACrypto struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// GenerateKeys generates a new pair of RSA keys (public and private).
func (r *RSACrypto) GenerateKeys(bits int) error {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	r.privateKey = privKey
	r.publicKey = &privKey.PublicKey
	return nil
}

// Encrypt encrypts the given plaintext using RSA with the public key.
func (r *RSACrypto) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	if r.publicKey == nil {
		return nil, errors.New("public key is not set")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using RSA with the private key.
func (r *RSACrypto) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, errors.New("private key is not set")
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
