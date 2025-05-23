/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"fmt"
	"io"
	"os"
)

const (
	fileModeUserReadWrite = 0o600
)

// encrypt encrypts data using the provided public key.
func encrypt(publicKey string, paasName string, data []byte) error {
	var encrypted string

	if c, err := NewCryptFromFiles([]string{}, publicKey, paasName); err != nil {
		return err
	} else if encrypted, err = c.Encrypt(data); err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	fmt.Println(encrypted)

	return nil
}

// DecryptFromStdin reads encrypted data from stdin, decrypts it using the
// provided private keys, and prints the decrypted result to stdout.
func DecryptFromStdin(privateKeys []string, paasName string) error {
	var encrypted, data []byte
	var err error

	if data, err = io.ReadAll(os.Stdin); err != nil {
		return err
	}

	if c, err := NewCryptFromFiles(privateKeys, "", paasName); err != nil {
		return err
	} else if encrypted, err = c.Decrypt(string(data)); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	fmt.Println(string(encrypted))
	return nil
}

// EncryptFromStdin reads input from standard input and returns an error or nil.
func EncryptFromStdin(publicKey string, paasName string) error {
	var data []byte
	var err error

	if data, err = io.ReadAll(os.Stdin); err != nil {
		return err
	}

	return encrypt(publicKey, paasName, data)
}

// EncryptFile encrypts the file at path using publicKey and paasName.
func EncryptFile(publicKey string, paasName string, path string) error {
	var data []byte
	var err error

	if data, err = os.ReadFile(path); err != nil {
		return err
	}

	return encrypt(publicKey, paasName, data)
}

// GenerateKeyPair generates a new public-private key pair or reuses existing ones.
func GenerateKeyPair(privateKey string, publicKey string) error {
	if privateKey == "" {
		f, err := os.CreateTemp("", "paas")
		if err != nil {
			return fmt.Errorf("privateKey not specified and failed to create temp file: %w", err)
		}

		privateKey = f.Name()
	}

	if publicKey == "" {
		f, err := os.CreateTemp("", "paas")
		if err != nil {
			return fmt.Errorf("privateKey not specified and failed to create temp file: %w", err)
		}

		publicKey = f.Name()
	}

	if _, err := NewGeneratedCrypt(privateKey, publicKey, ""); err != nil {
		return fmt.Errorf("failed to generate new key pair: %w", err)
	}
	return nil
}
