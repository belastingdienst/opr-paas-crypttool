/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/belastingdienst/opr-paas-crypttool/internal/paasfile"
	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v4/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert/yaml"
)

// FileOperations interface for file I/O operations (for testing)
type FileOperations interface {
	ReadFile(filename string) ([]byte, error)
	WriteFile(filename string, data []byte) error
	WriteFormattedFile(paas *v1alpha2.Paas, filename string, format paasfile.FileFormat) error
}

// DefaultFileOperations implements FileOperations using real file system
type DefaultFileOperations struct{}

// ReadFile reads a file and returns its contents.
func (f *DefaultFileOperations) ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// WriteFile writes a file with the given data.
func (f *DefaultFileOperations) WriteFile(filename string, data []byte) error {
	return paasfile.WriteFile(data, filename)
}

// WriteFormattedFile writes a Paas object to a file in the specified format.
func (f *DefaultFileOperations) WriteFormattedFile(paas *v1alpha2.Paas, filename string,
	format paasfile.FileFormat) error {
	return paasfile.WriteFormattedFile(paas, filename, format)
}

// CryptFactory interface for creating crypt instances (for testing)
type CryptFactory interface {
	NewCryptFromFiles(privateKeyFiles []string, publicKeyFile string, paasName string) (crypt.Cryptor, error)
}

// DefaultCryptFactory implements CryptFactory using real crypt operations
type DefaultCryptFactory struct{}

// NewCryptFromFiles implements CryptFactory.NewCryptFromFiles
func (c *DefaultCryptFactory) NewCryptFromFiles(privateKeyFiles []string, publicKeyFile string,
	paasName string) (crypt.Cryptor, error) {
	return crypt.NewCryptFromFiles(privateKeyFiles, publicKeyFile, paasName)
}

// ReencryptionResult holds the result of a reencryption operation
type ReencryptionResult struct {
	UpdatedPaas       *v1alpha2.Paas
	UpdatedPaasString string
	ErrorCount        int
}

// Service handles the core reencryption logic
type Service struct {
	fileOps      FileOperations
	cryptFactory CryptFactory
}

// NewReencryptService creates a new ReencryptService with default implementations
func NewReencryptService() *Service {
	return &Service{
		fileOps:      &DefaultFileOperations{},
		cryptFactory: &DefaultCryptFactory{},
	}
}

// NewReencryptServiceWithDeps creates a new ReencryptService with custom dependencies (for testing)
func NewReencryptServiceWithDeps(fileOps FileOperations, cryptFactory CryptFactory) *Service {
	return &Service{
		fileOps:      fileOps,
		cryptFactory: cryptFactory,
	}
}

// reencryptSecret decrypts and then re-encrypts a given secret using the provided
// source and destination crypt.Crypt instances.
func (s *Service) reencryptSecret(srcCrypt crypt.Cryptor, dstCrypt crypt.Cryptor,
	secret string) (string, error) {
	decrypted, err := srcCrypt.Decrypt(secret)
	if err != nil {
		return "", err
	}
	logrus.Debugf("decrypted: {checksum: %s, len: %d}", utils.HashData(decrypted), len(decrypted))

	reencrypted, err := dstCrypt.Encrypt(decrypted)
	if err != nil {
		return "", err
	}
	logrus.Debugf("reencrypted: {checksum: %s, len: %d}", utils.HashData([]byte(reencrypted)), len(reencrypted))

	return reencrypted, nil
}

// ReencryptPaasData performs the core reencryption logic on PAAS data
func (s *Service) ReencryptPaasData(paas *v1alpha2.Paas, paasAsString string,
	privateKeyFiles string, publicKeyFile string) (*ReencryptionResult, error) {
	paasName := paas.Name

	srcCrypt, err := s.cryptFactory.NewCryptFromFiles([]string{privateKeyFiles}, "", paasName)
	if err != nil {
		return nil, err
	}

	dstCrypt, err := s.cryptFactory.NewCryptFromFiles([]string{}, publicKeyFile, paasName)
	if err != nil {
		return nil, err
	}

	result := &ReencryptionResult{
		UpdatedPaas:       paas,
		UpdatedPaasString: paasAsString,
		ErrorCount:        0,
	}

	// Reencrypt main secrets
	for key, secret := range paas.Spec.Secrets {
		reencrypted, err := s.reencryptSecret(srcCrypt, dstCrypt, secret)
		if err != nil {
			result.ErrorCount++
			logrus.Errorf("failed to decrypt/reencrypt %s.spec.Secrets[%s]: %v", paasName, key, err)
			continue
		}

		paas.Spec.Secrets[key] = reencrypted
		result.UpdatedPaas = paas
		result.UpdatedPaasString = strings.ReplaceAll(result.UpdatedPaasString, strings.TrimSpace(secret), reencrypted)
		logrus.Infof("successfully reencrypted %s.spec.Secrets[%s]", paasName, key)
	}

	// Reencrypt capability secrets
	for capName, cap := range paas.Spec.Capabilities {
		errCount := s.reencryptCapSecrets(paasName, &result.UpdatedPaasString, capName, &cap, srcCrypt, dstCrypt)
		result.ErrorCount += errCount
	}

	return result, nil
}

// reencryptCapSecrets handles reencryption of capability secrets
func (s *Service) reencryptCapSecrets(paasName string, paasAsString *string, capName string,
	capability *v1alpha2.PaasCapability, srcCrypt, dstCrypt crypt.Cryptor) int {
	errNum := 0

	for key, secret := range capability.Secrets {
		reencrypted, err := s.reencryptSecret(srcCrypt, dstCrypt, secret)
		if err != nil {
			errNum++
			logrus.Errorf("failed to decrypt/reencrypt %s.spec.capabilities.%s.Secrets[%s]: %v",
				paasName, capName, key, err)
			continue
		}

		capability.Secrets[key] = reencrypted

		if paasAsString == nil {
			logrus.Errorf("paasAsString is nil.")
			errNum++
			return errNum
		}

		result := strings.ReplaceAll(*paasAsString, strings.TrimSpace(secret), reencrypted)
		paasAsString = &result
		logrus.Infof("successfully reencrypted %s.spec.capabilities[%s].Secrets[%s]", paasName, capName, key)
	}

	return errNum
}

// WriteReencryptedFile writes the reencrypted data to file based on output format
func (s *Service) WriteReencryptedFile(result *ReencryptionResult, fileName string, outputFormat string,
	originalFormat paasfile.FileFormat) error {
	var format paasfile.FileFormat

	switch outputFormat {
	case "json":
		format = paasfile.FiletypeJSON
	case "yaml":
		format = paasfile.FiletypeYAML
	default:
		format = originalFormat
	}

	if outputFormat == "preserved" {
		return s.fileOps.WriteFile(fileName, []byte(result.UpdatedPaasString))
	}

	return s.fileOps.WriteFormattedFile(result.UpdatedPaas, fileName, format)
}

// Files reencrypts the secrets of given PAAS files using the provided private
// and public keys.
func Files(privateKeyFiles string, publicKeyFile string, outputFormat string, files []string) error {
	service := NewReencryptService()
	return service.Files(privateKeyFiles, publicKeyFile, outputFormat, files)
}

// Files reencrypts the secrets of given PAAS files using the provided private
// and public keys.
func (s *Service) Files(privateKeyFiles string, publicKeyFile string, outputFormat string, files []string) error {
	var totalErrors int

	for _, fileName := range files {
		content, err := os.ReadFile(fileName)
		if err != nil {
			logrus.Warnf("Skipping file %s: could not read: %v", fileName, err)
			continue
		}

		// Check if it's a Paas object before proceeding
		if !isPaasObject(fileName, content) {
			logrus.Debugf("Skipping file %s: not a Paas object", fileName)
			continue
		}

		errNum, err := s.reencryptFile(fileName, privateKeyFiles, publicKeyFile, outputFormat)
		if err != nil {
			return err
		}
		totalErrors += errNum
	}

	errMsg := fmt.Errorf("finished with %d errors", totalErrors)
	if totalErrors > 0 {
		return errMsg
	}

	logrus.Info(errMsg)
	return nil
}

func isPaasObject(filePath string, content []byte) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	var data map[string]interface{}
	var err error

	switch ext {
	case ".json":
		err = json.Unmarshal(content, &data)
	case ".yaml", ".yml":
		err = yaml.Unmarshal(content, &data)
	default:
		return false
	}

	if err != nil {
		logrus.Debugf("Failed to parse %s: %v", filePath, err)
		return false
	}

	// Check if Kind field exists and equals "Paas"
	if kind, ok := data["Kind"].(string); ok && kind == "Paas" {
		return true
	}
	if kind, ok := data["kind"].(string); ok && kind == "Paas" {
		return true
	}

	return false
}

// reencryptFile handles the file-level reencryption logic
func (s *Service) reencryptFile(fileName string, privateKeyFiles string, publicKeyFile string,
	outputFormat string) (int, error) {
	// Read paas as bytes to preserve format
	paasAsBytes, err := s.fileOps.ReadFile(fileName)
	if err != nil {
		return 0, fmt.Errorf("could not read into string, file %s: %s", fileName, err)
	}
	paasAsString := string(paasAsBytes)

	// Read paas from file
	paas, format, err := paasfile.ReadPaasFile(fileName)
	if err != nil {
		return 0, fmt.Errorf("could not read file %s: %s", fileName, err)
	}

	// Perform reencryption
	result, err := s.ReencryptPaasData(paas, paasAsString, privateKeyFiles, publicKeyFile)
	if err != nil {
		return 0, err
	}

	// Write the result back to file
	err = s.WriteReencryptedFile(result, fileName, outputFormat, format)
	if err != nil {
		return 0, err
	}

	return result.ErrorCount, nil
}
