[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=shem-org_CryptoTool&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=shem-org_CryptoTool)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=shem-org_CryptoTool&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=shem-org_CryptoTool)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=shem-org_CryptoTool&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=shem-org_CryptoTool)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=shem-org_CryptoTool&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=shem-org_CryptoTool)
# CryptoTool

CryptoTool is an educational cryptography tool built in Golang. The project aims to implement both classic and modern encryption algorithms, such as AES, RSA, and others, to facilitate learning and understanding how these techniques work. Additionally, it is designed to be used as a library in future Go projects, providing functionalities for encrypting and decrypting data.

## Objectives

- Practice Go and study cryptography by implementing a variety of algorithms.
- Use the implemented functions as a library (`cryptoLib`) in other Go projects.
- Support both classical and modern cryptographic techniques.

## Features

- Additional algorithms coming soon

## Checklist of Cryptographic Implementations

This checklist tracks the progress of the cryptographic techniques implemented in CryptoTool. You can follow along as we continue to expand the project.

### Symmetric Encryption

- [x] **AES (Advanced Encryption Standard)**: Done
- [x] **Blowfish**: Done **(obsolete encryption)**
- [x] **ChaCha20**: Done
- [x] **DES (Data Encryption Standard)**: Done
- [x] **3DES (Triple DES)**: Done

### Asymmetric Encryption

- [X] **RSA (Rivest-Shamir-Adleman)**: Done
- [X] **ECC (Elliptic Curve Cryptography)**: Done
- [ ] **ElGamal**: Pending

### Hashing Algorithms

- [X] **SHA-256 (Secure Hash Algorithm 256)**: Done
- [ ] **SHA-3**: Pending
- [ ] **MD5**: Pending
- [ ] **RIPEMD-160**: Pending

### Digital Signatures

- [ ] **DSA (Digital Signature Algorithm)**: Pending
- [X] **ECDSA (Elliptic Curve Digital Signature Algorithm)**: Done
- [ ] **RSA Digital Signatures**: Pending

### Stream Ciphers

- [ ] **RC4 (Rivest Cipher 4)**: Pending
- [ ] **Salsa20**: Pending

### Message Authentication Codes (MAC)

- [x] **HMAC (Hash-based Message Authentication Code)**: Done
- [ ] **CMAC (Cipher-based Message Authentication Code)**: Pending

### Key Derivation Functions

- [ ] **PBKDF2 (Password-Based Key Derivation Function 2)**: Pending
- [ ] **bcrypt**: Pending
- [x] **scrypt**: Done

## Usage

To use CryptoTool as a library in your Go projects, import the necessary packages and call the encryption or decryption functions.
