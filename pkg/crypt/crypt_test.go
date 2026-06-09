/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package crypt

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRsaGenerate(t *testing.T) {
	context := "context"
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Crypt object created")
	assert.NotNil(t, c, "Crypt object is not nil")
}

func TestRsa(t *testing.T) {
	context := "context"

	// generate private/public keys
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context)

	require.NoError(t, err, "Getting New Crypt")

	original := "WOEPTIDOE"

	encrypted, err := c.EncryptRsa([]byte(original))
	require.NoError(t, err, "Encrypting data")

	decrypted, err := c.DecryptRsa(encrypted)
	require.NoError(t, err, "Decrypting data")
	assert.Equal(t, string(decrypted), string(original))
}

func TestEncryptingAndDecrypting(t *testing.T) {
	const (
		minimalEncryptedLength = 100
	)
	var (
		original = "Dit is een test"
		context1 = "context1"
		context2 = "context2"
	)

	// generate private/public keys
	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	c, err := NewGeneratedCrypt(priv.Name(), pub.Name(), context1)
	require.NoError(t, err, "Getting New Crypt")

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting")
	assert.Greater(t, len(encrypted), minimalEncryptedLength)

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))

	c.encryptionContext = []byte(context2)
	_, err = c.Decrypt(encrypted)
	require.Error(t, err, "Decrypting with other context")
	encrypted, err = c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting with other context should succeed")
	decrypted, err = c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting with other context")
	assert.Equal(t, original, string(decrypted))
}

func TestNewCryptFromKeysWithPublicKeyPath(t *testing.T) {
	context := "context"
	original := "Dit is een test"

	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	_, err = NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Generating keys")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv.Name()})
	require.NoError(t, err, "Reading private key")

	c, err := NewCryptFromKeys(privateKeys, pub.Name(), context)
	require.NoError(t, err, "Getting New Crypt from public key path")

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))
}

func TestNewCryptFromKeysWithEmptyPublicKeyPath(t *testing.T) {
	context := "context"

	priv1, err := os.CreateTemp("", "private1")
	require.NoError(t, err, "Creating tempfile for first private key")
	defer os.Remove(priv1.Name()) // clean up

	pub1, err := os.CreateTemp("", "public1")
	require.NoError(t, err, "Creating tempfile for first public key")
	defer os.Remove(pub1.Name()) // clean up

	priv2, err := os.CreateTemp("", "private2")
	require.NoError(t, err, "Creating tempfile for second private key")
	defer os.Remove(priv2.Name()) // clean up

	pub2, err := os.CreateTemp("", "public2")
	require.NoError(t, err, "Creating tempfile for second public key")
	defer os.Remove(pub2.Name()) // clean up

	_, err = NewGeneratedCrypt(priv1.Name(), pub1.Name(), context)
	require.NoError(t, err, "Generating first key")
	_, err = NewGeneratedCrypt(priv2.Name(), pub2.Name(), context)
	require.NoError(t, err, "Generating second key")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv1.Name(), priv2.Name()})
	require.NoError(t, err, "Reading private keys")

	c, err := NewCryptFromKeys(privateKeys, "", context)
	require.NoError(t, err, "Getting New Crypt without public key")
	assert.NotNil(t, c)
	assert.Nil(t, c.publicKey)
}

func TestNewCryptFromKeysWithNilPublicKey(t *testing.T) {
	context := "context"
	original := "Dit is een test"

	priv, err := os.CreateTemp("", "private")
	require.NoError(t, err, "Creating tempfile for private key")
	defer os.Remove(priv.Name()) // clean up

	pub, err := os.CreateTemp("", "public")
	require.NoError(t, err, "Creating tempfile for public key")
	defer os.Remove(pub.Name()) // clean up

	_, err = NewGeneratedCrypt(priv.Name(), pub.Name(), context)
	require.NoError(t, err, "Generating keys")

	privateKeys, err := NewPrivateKeysFromFiles([]string{priv.Name()})
	require.NoError(t, err, "Reading private key")

	c, err := NewCryptFromKeys(privateKeys, nil, context)
	require.NoError(t, err, "Getting New Crypt without public key")
	assert.Nil(t, c.publicKey)

	encrypted, err := c.Encrypt([]byte(original))
	require.NoError(t, err, "Encrypting with public key derived from private key")

	decrypted, err := c.Decrypt(encrypted)
	require.NoError(t, err, "Decrypting")
	assert.Equal(t, original, string(decrypted))
}
