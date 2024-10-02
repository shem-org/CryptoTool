package rsa

import (
	"fmt"
	"testing"
)

func TestRSACrypto(t *testing.T) {
	// Subteste para geração de chaves
	t.Run("GenerateKeys", func(t *testing.T) {
		crypto := &RSACrypto{}
		err := crypto.GenerateKeys(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}
		if crypto.privateKey == nil || crypto.publicKey == nil {
			t.Fatalf("Keys should not be nil after generation")
		}
	})

	// Subteste para criptografia e descriptografia bem-sucedidas
	t.Run("EncryptDecryptSuccess", func(t *testing.T) {
		crypto := &RSACrypto{}
		err := crypto.GenerateKeys(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		plaintext := []byte("Hello, RSA encryption!")
		ciphertext, err := crypto.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		decrypted, err := crypto.Decrypt(ciphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Fatalf("Expected %s, got %s", plaintext, decrypted)
		}
	})

	// Subteste para falha de descriptografia (sem chave privada)
	t.Run("DecryptWithoutPrivateKey", func(t *testing.T) {
		crypto := &RSACrypto{}
		err := crypto.GenerateKeys(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA keys: %v", err)
		}

		// Criar uma nova instância que não tem a chave privada
		cryptoNoPrivateKey := &RSACrypto{publicKey: crypto.publicKey}

		plaintext := []byte("Hello, RSA encryption!")
		ciphertext, err := crypto.Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt: %v", err)
		}

		_, err = cryptoNoPrivateKey.Decrypt(ciphertext, nil)
		if err == nil {
			t.Fatal("Expected error when decrypting without private key, but got none")
		}
	})

	// Subteste para chaves de diferentes tamanhos
	t.Run("KeySizeVariations", func(t *testing.T) {
		keySizes := []int{1024, 2048, 4096}
		for _, size := range keySizes {
			t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
				crypto := &RSACrypto{}
				err := crypto.GenerateKeys(size)
				if err != nil {
					t.Fatalf("Failed to generate RSA keys with size %d: %v", size, err)
				}

				plaintext := []byte("Test with key size")
				ciphertext, err := crypto.Encrypt(plaintext, nil)
				if err != nil {
					t.Fatalf("Failed to encrypt with key size %d: %v", size, err)
				}

				decrypted, err := crypto.Decrypt(ciphertext, nil)
				if err != nil {
					t.Fatalf("Failed to decrypt with key size %d: %v", size, err)
				}

				if string(decrypted) != string(plaintext) {
					t.Fatalf("Expected %s with key size %d, got %s", plaintext, size, decrypted)
				}
			})
		}
	})
}
