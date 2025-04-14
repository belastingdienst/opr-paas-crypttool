/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
)

// PrivateKeys is an interface for handling multiple private keys (for rotation)
// and storing them in a list of PrivateKey's.
type PrivateKeys []*PrivateKey

// NewPrivateKeysFromFiles returns a Crypt based on the provided privateKeyPaths
func NewPrivateKeysFromFiles(privateKeyPaths []string) (PrivateKeys, error) {
	var privateKeys PrivateKeys
	var pk *PrivateKey
	var files []string
	var err error

	if files, err = utils.PathToFileList(privateKeyPaths); err != nil {
		return nil, fmt.Errorf("could not find files in '%v': %w", privateKeyPaths, err)
	}

	for _, file := range files {
		if pk, err = NewPrivateKeyFromFile(file); err != nil {
			return nil, fmt.Errorf("invalid private key file %s", file)
		}

		privateKeys = append(privateKeys, pk)
	}

	return privateKeys, nil
}

// NewPrivateKeysFromSecretData returns a Crypt based on the provided privateKeyPaths
func NewPrivateKeysFromSecretData(privateKeyData map[string][]byte) (PrivateKeys, error) {
	var privateKeys PrivateKeys
	var privateKey *PrivateKey
	var err error

	for name, value := range privateKeyData {
		if privateKey, err = NewPrivateKeyFromPem(name, value); err != nil {
			return nil, err
		}

		privateKeys = append(privateKeys, privateKey)
	}

	return privateKeys, nil
}

// Compare checks 2 sets of private keys
func (pks PrivateKeys) Compare(other PrivateKeys) (same bool) {
	if len(pks) != len(other) {
		return false
	}

	for index, key := range pks {
		if !key.privateKey.Equal(other[index]) {
			return false
		}
	}

	return true
}

// AsSecretData returns the private keys as a map of string to byte slices.
// This is used when we need to persist the secret data in some form,
// such as storing it in a database or passing it through an API call.
//
// @return data A map where each key is the path to the corresponding private key
//
//	and the value is the PEM encoded representation of that key.
func (pks PrivateKeys) AsSecretData() (data map[string][]byte) {
	data = map[string][]byte{}
	for _, key := range pks {
		data[key.privateKeyPath] = key.privateKeyPem
	}
	return data
}

// A PrivateKey is used for decryption of encrypted secrets
type PrivateKey struct {
	privateKeyPath string
	privateKeyPem  []byte
	privateKey     *rsa.PrivateKey
}

// NewPrivateKeyFromFile returns a CryptPrivateKey from a privateKeyFilePath
func NewPrivateKeyFromFile(privateKeyPath string) (*PrivateKey, error) {
	var privateKeyPem []byte
	var err error

	if privateKeyPath == "" {
		return nil, fmt.Errorf("cannot get private key without a specified path")
	}
	if privateKeyPem, err = os.ReadFile(privateKeyPath); err != nil {
		panic(err)
	}

	return NewPrivateKeyFromPem(privateKeyPath, privateKeyPem)
}

// NewPrivateKeyFromPem returns a CryptPrivateKey from a privateKeyFilePath
func NewPrivateKeyFromPem(privateKeyPath string, privateKeyPem []byte) (*PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	return &PrivateKey{
		privateKeyPath,
		privateKeyPem,
		privateKey,
	}, nil
}

// WritePrivateKey writes a private key to a file at the specified path.
func (pk *PrivateKey) writePrivateKey() error {
	if pk.privateKeyPath == "" {
		return fmt.Errorf("cannot write private key without a specified path")
	}
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(pk.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	if err := os.WriteFile(pk.privateKeyPath, privateKeyPEM, fileModeUserReadWrite); err != nil {
		return fmt.Errorf("unable to write private key: %w", err)
	}
	fmt.Printf("Private key written to %s\n", pk.privateKeyPath)
	return nil
}

// getPrivateKey returns the rsa.PrivateKey from the provided CryptPrivateKey.
//
// If it is not set yet, it will try to load it from the specified filePath. It
// also checks whether it is a valid PrivateKey.
func (pk *PrivateKey) getPrivateKey() (privateKey *rsa.PrivateKey, err error) {
	var privateRsaKey *rsa.PrivateKey

	// if privateKey is already loaded, return it from the CryptPrivateKey
	if pk.privateKey != nil {
		return pk.privateKey, nil
	} else if len(pk.privateKeyPem) == 0 {
		return nil, fmt.Errorf("invalid private key (Pem not set)")
	}

	// load privateKey from privateKeyPem
	if privateKeyBlock, _ := pem.Decode(pk.privateKeyPem); privateKeyBlock == nil {
		return nil, fmt.Errorf("cannot decode private key")
		// sanity check if the privatekey is a valid one
	} else if privateRsaKey, err = x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("private key invalid: %w", err)
	}

	pk.privateKey = privateRsaKey
	return pk.privateKey, nil
}

// DecryptRsa decrypts data that was previously encrypted using RSA.
//
// Decryption is performed blockwise to prevent exceeding the maximum size for a
// single AES encryption operation.
//
// For an input message of length msgLen, it will attempt to process in chunks of
// step bytes, where step is the size of the private key.
func (pk *PrivateKey) DecryptRsa(data []byte, encryptionContext []byte) (decryptedBytes []byte, err error) {
	var privateKey *rsa.PrivateKey

	if privateKey, err = pk.getPrivateKey(); err != nil {
		return nil, err
	}

	hash := sha512.New()
	msgLen := len(data)
	step := privateKey.Size()
	random := rand.Reader

	for start := 0; start < msgLen; start += step {
		finish := min(start+step, msgLen)

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, privateKey, data[start:finish], encryptionContext)
		if err != nil {
			return nil, err
		}
		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}
	return decryptedBytes, nil
}
