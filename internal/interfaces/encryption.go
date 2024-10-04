package interfaces

// Crypto defines the basic operations that all encryption algorithms should implement.
type Crypto interface {
	Encrypt(data []byte, key interface{}) ([]byte, error)
	Decrypt(data []byte, key interface{}) ([]byte, error)
}

// Hash defines the operations that all hashing algorithms should implement.
type Hash interface {
	Hash(data []byte) (string, error)
}
