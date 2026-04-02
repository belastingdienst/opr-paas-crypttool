package reencrypt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
)

// Reencrypt reencrypts the secrets of given PAAS files using the provided private
// and public keys.
func (s *ConversionService) Reencrypt(
	outputFormat paasfile.Format,
	files []string,
) error {
	var errs []error

	for _, fileName := range files {
		file := paasfile.File{Path: fileName}

		err := s.reencryptPaasFile(file, outputFormat)
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		err := fmt.Errorf("finished with errors: %e", errors.Join(errs...))
		logrus.Error(err)
		return err
	}

	logrus.Info("finished")
	return nil
}

// reencryptSecret decrypts and then re-encrypts a given secret using the provided
// source and destination crypt.Crypt instances.
func (s *ConversionService) reencryptSecret(crypter crypt.Cryptor,
	secret string,
) (string, error) {
	decrypted, err := crypter.Decrypt(secret)
	if err != nil {
		return "", err
	}
	logrus.Debugf("decrypted: {checksum: %s, len: %d}", utils.HashData(decrypted), len(decrypted))

	reencrypted, err := crypter.Encrypt(decrypted)
	if err != nil {
		return "", err
	}
	logrus.Debugf("reencrypted: {checksum: %s, len: %d}", utils.HashData([]byte(reencrypted)), len(reencrypted))

	return reencrypted, nil
}

// reencryptCapSecrets handles reencryption of capability secrets
func (s *ConversionService) reencryptCapSecrets(paasName string, capName string,
	capability *v1alpha2.PaasCapability, srcCrypt crypt.Cryptor,
) []error {
	var errs []error
	for key, secret := range capability.Secrets {
		reencrypted, err := s.reencryptSecret(srcCrypt, secret)
		if err != nil {
			err := fmt.Errorf("failed to decrypt/reencrypt %s.spec.capabilities.%s.Secrets[%s]: %v",
				paasName, capName, key, err)
			errs = append(errs, err)
			logrus.Error(err)
			continue
		}

		capability.Secrets[key] = reencrypted
		logrus.Infof("successfully reencrypted %s.spec.capabilities[%s].Secrets[%s]", paasName, capName, key)
	}

	return errs
}

// ReencryptPaasFile performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaas(paas *v1alpha2.Paas) error {
	var errs []error
	paasName := paas.Name

	crypter, err := s.Factory.GetCrypt(paasName)
	if err != nil {
		return err
	}

	// Reencrypt main secrets
	for key, secret := range paas.Spec.Secrets {
		reencrypted, err := s.reencryptSecret(crypter, secret)
		if err != nil {
			err := fmt.Errorf("failed to decrypt/reencrypt %s.spec.Secrets[%s]: %v", paasName, key, err)
			errs = append(errs, err)
			logrus.Error(err)
			continue
		}

		paas.Spec.Secrets[key] = reencrypted
		logrus.Debugf("successfully reencrypted %s.spec.Secrets[%s]", paasName, key)
	}

	// Reencrypt capability secrets
	for capName, cap := range paas.Spec.Capabilities {
		errs = append(errs, s.reencryptCapSecrets(paasName, capName, &cap, crypter)...)
	}
	return errors.Join(errs...)
}

// reencryptPaasFile performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaasFile(file paasfile.File, format paasfile.Format) error {
	hdr, err := file.GetHeader()
	if err != nil {
		return err
	}
	if err := hdr.Verify(); err != nil {
		return err
	}
	if format == paasfile.PreserveFormat {
		return s.reencryptPaasFilePreserved(&file)
	}
	paas, err := file.GetPaas()
	if err != nil {
		return err
	}
	if err := s.reencryptPaas(paas); err != nil {
		return err
	}
	file.SetPaas(*paas)
	return file.Write("", format)
}

func (s *ConversionService) getSecrets(file *paasfile.File) (map[string]string, error) {
	paas, err := file.GetPaas()
	if err != nil {
		return nil, err
	}

	paasName := paas.Name

	crypter, err := s.Factory.GetCrypt(paasName)
	if err != nil {
		return nil, err
	}
	var errs []error
	// Reencrypt main secrets
	secrets := map[string]string{}
	for key, secret := range paas.Spec.Secrets {
		reencrypted, err := s.reencryptSecret(crypter, secret)
		if err != nil {
			errs = append(errs, err)
			logrus.Errorf("failed to decrypt/reencrypt %s.spec.Secrets[%s]: %v", paasName, key, err)
			continue
		}
		secrets[secret] = reencrypted
		logrus.Infof("successfully reencrypted %s.spec.Secrets[%s]", paasName, key)
	}

	// Reencrypt capability secrets
	for capName, cap := range paas.Spec.Capabilities {
		for key, secret := range cap.Secrets {
			reencrypted, err := s.reencryptSecret(crypter, secret)
			if err != nil {
				errs = append(errs, err)
				logrus.Errorf("failed to decrypt/reencrypt %s.spec.Capabilities[%s].Secrets[%s]: %v",
					paasName, capName, key, err)
				continue
			}
			secrets[secret] = reencrypted
			logrus.Infof("successfully reencrypted %s.spec.Capabilities[%s].Secrets[%s]", paasName, capName, key)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return secrets, nil
}

// reencryptPaasFilePreserved performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaasFilePreserved(file *paasfile.File) error {
	secrets, err := s.getSecrets(file)
	if err != nil {
		return err
	}
	content, err := file.GetContent()
	if err != nil {
		return err
	}
	paasAsString := string(content)

	// Reencrypt main secrets
	for secret, reencrypted := range secrets {
		paasAsString = strings.ReplaceAll(paasAsString, strings.TrimSpace(secret), reencrypted)
	}
	file.SetContent([]byte(paasAsString))
	file.WriteContent("")
	return nil
}
