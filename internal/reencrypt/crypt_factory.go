package reencrypt

import "github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"

// CryptFactory interface for creating crypt instances (for testing)
type CryptFactory interface {
	GetCrypt(paasName string) (crypt.Cryptor, error)
}

// FileCryptFactory implements CryptFactory using real crypt operations
type FileCryptFactory struct {
	PrivateKeyFiles []string
	PublicKeyFile   string
}

// GetCrypt implements CryptFactory.GetCrypt
func (c *FileCryptFactory) GetCrypt(paasName string) (crypt.Cryptor, error) {
	return crypt.NewCryptFromFiles(c.PrivateKeyFiles, c.PublicKeyFile, paasName)
}

// KeyCryptFactory implements CryptFactory using real crypt operations
type KeyCryptFactory struct {
	Keys crypt.PrivateKeys
}

// GetCrypt implements CryptFactory.GetCrypt
func (c *KeyCryptFactory) GetCrypt(paasName string) (crypt.Cryptor, error) {
	return crypt.NewCryptFromKeys(c.Keys, nil, paasName)
}
