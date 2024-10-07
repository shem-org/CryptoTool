package blowfish

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/shem-org/CryptoTool/internal/interfaces"
	"golang.org/x/crypto/blowfish"
)

var _ interfaces.Crypto = (*BlowfishCrypto)(nil)

// BlowfishCrypto implements the Crypto interface for Blowfish
type BlowfishCrypto struct{}

// Encrypt performs encryption using Blowfish
func (c *BlowfishCrypto) Encrypt(plaintext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	// Create a new Blowfish cipher with the given key
	block, err := blowfish.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Blowfish cipher: %w", err)
	}

	// Prepare for encryption with a block cipher mode, such as CBC or CFB
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	// Prepend IV to the ciphertext
	return append(iv, ciphertext...), nil
}

// Decrypt performs decryption using Blowfish
func (c *BlowfishCrypto) Decrypt(ciphertext []byte, key interface{}) ([]byte, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return nil, errors.New("the provided key is not of type []byte")
	}

	// Create a new Blowfish cipher with the given key
	block, err := blowfish.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create Blowfish cipher: %w", err)
	}

	if len(ciphertext) < block.BlockSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Split the IV and the actual ciphertext
	iv, ciphertext := ciphertext[:block.BlockSize()], ciphertext[block.BlockSize():]

	// Prepare for decryption
	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
