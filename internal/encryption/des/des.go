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

// Encrypt performs encryption using DES with a 56-bit key
func (d *DESCrypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != 7 {
		return nil, errors.New("the key must be 7 bytes for DES (56 bits)")
	}

	// Add a parity bit to make it 8 bytes
	desKey := addParityBit(keyBytes)

	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}

	// Add padding if the plaintext is not a multiple of the block size
	plaintext = pkcs5Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))

	// Using the first 8 bytes as IV
	mode := cipher.NewCBCEncrypter(block, desKey[:8])
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// Decrypt performs decryption using DES with a 56-bit key
func (d *DESCrypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	if len(keyBytes) != 7 {
		return nil, errors.New("the key must be 7 bytes for DES (56 bits)")
	}

	// Add a parity bit to make it 8 bytes
	desKey := addParityBit(keyBytes)

	block, err := des.NewCipher(desKey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	// Using the first 8 bytes as IV
	mode := cipher.NewCBCDecrypter(block, desKey[:8])
	mode.CryptBlocks(plaintext, ciphertext)

	// Verify that the decrypted plaintext has valid padding
	if len(plaintext) == 0 || len(plaintext)%block.BlockSize() != 0 {
		return nil, errors.New("decryption failed, invalid padding")
	}

	// Remove padding from decrypted text
	plaintext, err = pkcs5UnPaddingSafe(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// addParityBit adds a parity bit to a 7-byte key to make it 8 bytes
func addParityBit(key []byte) []byte {
	parityKey := make([]byte, 8)
	copy(parityKey, key)
	// Optionally: Add parity calculation if required by your system
	return parityKey
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

func pkcs5UnPaddingSafe(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("invalid padding")
	}
	unpadding := int(src[length-1])

	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding size")
	}

	return src[:(length - unpadding)], nil
}
