/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
)

// AESKeySize is the key size of AES in bits.
const AESKeySize = 4096

// Crypt represents a cryptographic object that performs various encryption and
// decryption tasks.
type Crypt struct {
	privateKeys       PrivateKeys
	publicKeyPath     string
	publicKey         *rsa.PublicKey
	encryptionContext []byte
}

// NewCryptFromFiles returns a Crypt based on the provided privateKeyPaths and publicKeyPath using the encryptionContext
func NewCryptFromFiles(privateKeyPaths []string, publicKeyPath string, encryptionContext string) (*Crypt, error) {
	privateKeys, err := NewPrivateKeysFromFiles(privateKeyPaths)
	if err != nil {
		return nil, err
	}
	return NewCryptFromKeys(privateKeys, publicKeyPath, encryptionContext)
}

// NewCryptFromKeys returns a Crypt based on the provided privateKeys and publicKey using the encryptionContext
func NewCryptFromKeys(privateKeys PrivateKeys, publicKeyPath string, encryptionContext string) (*Crypt, error) {
	if publicKeyPath != "" {
		publicKeyPaths := []string{publicKeyPath}
		if _, err := utils.PathToFileList(publicKeyPaths); err != nil {
			return nil, fmt.Errorf("could not find files in '%v': %w", publicKeyPaths, err)
		}
	}

	return &Crypt{
		privateKeys:       privateKeys,
		publicKeyPath:     publicKeyPath,
		encryptionContext: []byte(encryptionContext),
	}, nil
}

// NewGeneratedCrypt generates a new Crypt instance with randomly generated private
// and public key pairs.
//
// The keys are stored on disk at the specified paths, and can be retrieved via
// the returned Crypt instance.
//
// This method returns an error if it is unable to generate a valid key pair or
// write the keys to disk.
func NewGeneratedCrypt(privateKeyPath string, publicKeyPath string, context string) (*Crypt, error) {
	var privateKey *rsa.PrivateKey
	var err error

	c := Crypt{
		encryptionContext: []byte(context),
	}
	if privateKey, err = rsa.GenerateKey(rand.Reader, AESKeySize); err != nil {
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}

	pk := PrivateKey{
		privateKey:     privateKey,
		privateKeyPath: privateKeyPath,
	}
	c.privateKeys = PrivateKeys{&pk}
	if err := pk.writePrivateKey(); err != nil {
		return nil, err
	}

	c.publicKeyPath = publicKeyPath
	c.publicKey = &privateKey.PublicKey
	if err := c.writePublicKey(); err != nil {
		return nil, err
	}

	return &c, nil
}

// WritePublicKey writes the public key of the RSA private key to a file.
//
// If a path was specified when creating the Crypt object, the public key will be written
// to that location. The format used is PEM-encoded ASN.1 (RFC 1421).
func (c *Crypt) writePublicKey() error {
	var publicKeyBytes []byte
	var err error

	if c.publicKeyPath == "" {
		return errors.New("cannot write public key without a specified path")
	}
	if publicKeyBytes, err = x509.MarshalPKIXPublicKey(c.publicKey); err != nil {
		return fmt.Errorf("unable to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err = os.WriteFile(c.publicKeyPath, publicKeyPEM, fileModeUserReadWrite); err != nil {
		return fmt.Errorf("unable to write public key: %w", err)
	}

	fmt.Printf("Public key written to %s\n", c.publicKeyPath)
	return nil
}

// getPublicKey retrieves and returns the public key associated with this Crypt instance.
//
// If the public key has already been loaded, it is returned immediately. Otherwise,
// the public key is read from the file specified by publicKeyPath if provided.
// If the file does not exist or cannot be decoded as a valid RSA public key, an error
// is returned.
func (c *Crypt) getPublicKey() (*rsa.PublicKey, error) {
	var publicRsaKey *rsa.PublicKey
	var ok bool

	if c.publicKey != nil {
		return c.publicKey, nil
	}
	if c.publicKeyPath == "" {
		return nil, errors.New("cannot get public key without a specified path")
	}
	if publicKeyPEM, err := os.ReadFile(c.publicKeyPath); err != nil {
		panic(err)
	} else if publicKeyBlock, _ := pem.Decode(publicKeyPEM); publicKeyBlock == nil {
		return nil, errors.New("cannot decode public key")
	} else if publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("public key invalid: %w", err)
	} else if publicRsaKey, ok = publicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("public key not rsa public key")
	}

	c.publicKey = publicRsaKey

	return c.publicKey, nil
}

// EncryptRsa encrypts the provided secret using RSA-OAEP encryption with the public key.
func (c *Crypt) EncryptRsa(secret []byte) (encryptedBytes []byte, err error) {
	var publicKey *rsa.PublicKey
	var encryptedBlock []byte

	if publicKey, err = c.getPublicKey(); err != nil {
		return nil, err
	}

	random := rand.Reader
	hash := sha512.New()
	msgLen := len(secret)
	step := publicKey.Size() - 2*hash.Size() - 2
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlock, err = rsa.EncryptOAEP(hash, random, publicKey, secret[start:finish], c.encryptionContext)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlock...)
	}
	return encryptedBytes, nil
}

// Encrypt encrypts the secret using asymmetric encryption and returns the result
// as a base64-encoded string.
func (c *Crypt) Encrypt(secret []byte) (encrypted string, err error) {
	var asymEncrypted []byte

	if asymEncrypted, err = c.EncryptRsa(secret); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(asymEncrypted), nil
}

// DecryptRsa attempts to decrypt given data using RSA private keys.
// It will try each key until it successfully decrypts the data or runs out of keys.
func (c *Crypt) DecryptRsa(data []byte) (decryptedBytes []byte, err error) {
	if len(c.privateKeys) < 1 {
		return nil, errors.New("cannot decrypt without any private key")
	}
	for _, pk := range c.privateKeys {
		if decryptedBytes, err = pk.DecryptRsa(data, c.encryptionContext); err != nil {
			continue
		}

		return decryptedBytes, nil
	}
	return nil, errors.New("unable to decrypt data with any of the private keys")
}

// Decrypt decrypts an asymmetrically encrypted message using base64.
func (c Crypt) Decrypt(b64 string) ([]byte, error) {
	var decrypted []byte

	// Removing all characters that do not comply to base64 encoding (mainly \n and ' ')
	re := regexp.MustCompile("[^ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]")
	b64 = re.ReplaceAllLiteralString(b64, "")
	if asymEncrypted, err := base64.StdEncoding.DecodeString(b64); err != nil {
		return nil, err
	} else if decrypted, err = c.DecryptRsa(asymEncrypted); err != nil {
		return nil, err
	}

	return decrypted, nil
}
