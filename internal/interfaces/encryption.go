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

// HMAC defines the operations that all HMAC algorithms should implement.
type HMAC interface {
	GenerateHMAC(data, key []byte) ([]byte, error)
	VerifyHMAC(data, key, hmacValue []byte) (bool, error)
}

// PasswordHasher defines the operations for password hashing algorithms like bcrypt and scrypt.
type PasswordHasher interface {
	HashPassword(password []byte) ([]byte, error)
	CompareHashAndPassword(hashedPassword, password []byte) (bool, error)
}
