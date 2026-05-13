/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

// ConversionService handles the core conversion logic
type ConversionService struct {
	Factory CryptFactory
}

// NewConversionService creates a new ReencryptService with default implementations
func NewConversionService(privateKeyFiles []string, publicKeyFile string) *ConversionService {
	return &ConversionService{
		Factory: &FileCryptFactory{
			PrivateKeyFiles: privateKeyFiles,
			PublicKeyFile:   publicKeyFile,
		},
	}
}
