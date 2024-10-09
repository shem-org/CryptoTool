package ecc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

type ECCCrypto struct{}

// Encrypt encrypts the given plaintext using the provided ECDSA public key.
func (e *ECCCrypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	// ECC encryption is not supported directly like RSA, it uses ECDH or ECIES schemes.
	return nil, errors.New("ECC encryption is not directly supported, consider using ECDH or ECIES")
}

// Decrypt decrypts the given ciphertext using the provided ECDSA private key.
func (e *ECCCrypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	// ECC decryption is not supported directly like RSA, it uses ECDH or ECIES schemes.
	return nil, errors.New("ECC decryption is not directly supported, consider using ECDH or ECIES")
}

// Sign generates an ECDSA signature for the given data using the provided private key.
func (e *ECCCrypto) Sign(data []byte, key interface{}) ([]byte, error) {
	privKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key type for ECDSA")
	}

	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %v", err)
	}

	// Concatenate r and s values to return the signature
	signature := append(r.Bytes(), s.Bytes()...)
	return signature, nil
}

// Verify verifies an ECDSA signature for the given data using the provided public key.
func (e *ECCCrypto) Verify(data, signature []byte, key interface{}) (bool, error) {
	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("invalid public key type for ECDSA")
	}

	hash := sha256.Sum256(data)

	// Split signature into r and s
	r := new(big.Int).SetBytes(signature[:len(signature)/2])
	s := new(big.Int).SetBytes(signature[len(signature)/2:])

	valid := ecdsa.Verify(pubKey, hash[:], r, s)
	return valid, nil
}

// GenerateECCKeys generates a new pair of ECDSA keys (private and public).
func GenerateECCKeys(curve elliptic.Curve) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pubKey := &privKey.PublicKey
	return privKey, pubKey, nil
}
