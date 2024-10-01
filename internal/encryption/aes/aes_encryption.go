package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

// AESCrypto implements the Crypto interface for AES encryption and decryption.
type AESCrypto struct{}

// Encrypt encrypts the given plaintext using AES with the provided key.
func (a *AESCrypto) Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Allocate space for the ciphertext (IV + encrypted data)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Get the IV (initialization vector) from the beginning of the ciphertext
	iv := ciphertext[:aes.BlockSize]

	// Create the encryption stream using CFB mode
	stream := cipher.NewCFBEncrypter(block, iv)

	// Encrypt the plaintext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext using AES with the provided key.
func (a *AESCrypto) Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Extract the IV (initialization vector) from the beginning of the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Create the decryption stream using CFB mode
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt the ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}
