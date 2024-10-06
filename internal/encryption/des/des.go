package des

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"errors"

	"github.com/shem-org/CryptoTool/internal/interfaces"
)

var _ interfaces.Crypto = (*DESCrypto)(nil)

// DESCrypto implements the Crypto interface for DES
type DESCrypto struct{}

// Encrypt performs encryption using DES
func (d *DESCrypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != 8 {
		return nil, errors.New("the key must be 8 bytes for DES")
	}

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	// Add padding if the plaintext is not a multiple of the block size
	plaintext = pkcs5Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))

	// Using the first 8 bytes as IV
	mode := cipher.NewCBCEncrypter(block, keyBytes[:8])
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// Decrypt performs decryption using DES
func (d *DESCrypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != 8 {
		return nil, errors.New("the key must be 8 bytes for DES")
	}

	block, err := des.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	// Using the first 8 bytes as IV
	mode := cipher.NewCBCDecrypter(block, keyBytes[:8])
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding from decrypted text
	plaintext = pkcs5UnPadding(plaintext)

	return plaintext, nil
}

// pkcs5Padding adds padding to the input based on PKCS5 standard
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// pkcs5UnPadding removes padding from the input based on PKCS5 standard
func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
