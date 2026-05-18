package reencrypt

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasobject"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
)

// ReencryptObjects can process a list of PaasObject types, for each retrieving a Paas from a PaasObject interface
// datatype, reencrypt it, and writing it back.
func (s *ConversionService) ReencryptObjects(
	os []paasobject.Object,
	labelFilters string,
	annotationFilters string,
) error {
	var errs []error

	for _, o := range os {
		err := s.reencryptPaasObject(o, labelFilters, annotationFilters)
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
	if paas == nil {
		return errors.New("cannot reencrypt a nilpaas")
	}
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

func isFiltered(labels map[string]string, filters string) (bool, error) {
	var labelKVSplitter = regexp.MustCompile("^([^!=]*)(!?)=(.*)")

	if labels == nil {
		return false, nil
	}
	if filters == "" {
		return false, nil
	}
	for _, filter := range strings.Split(filters, ",") {
		var (
			fKey   string
			negate bool
			fValue string
		)
		kv := labelKVSplitter.FindStringSubmatch(filter)
		if len(kv) < 2 {
			fKey = filter
		} else {
			fKey = kv[1]
		}
		if len(kv) > 2 {
			negate = (kv[2] == "!")
		}
		if len(kv) > 3 {
			fValue = kv[3]
		}

		logrus.Debugf("filter: %s (%s %b %s) %v", filter, fKey, negate, fValue, kv)

		labelVal, exists := labels[fKey]
		if !exists {
			continue
		}
		if fValue == "" {
			return true, nil
		}
		if labelVal == fValue {
			return negate, nil
		}
	}
	return false, nil
}

// reencryptPaasFile performs the core reencryption logic on PAAS data
func (s *ConversionService) reencryptPaasObject(
	object paasobject.Object,
	labelFilters string,
	annotationFilters string,
) error {
	paas, err := object.GetPaas()
	if err != nil {
		return err
	}
	logrus.Debugf("anno selector %s", annotationFilters)
	if isAnnoFlt, err := isFiltered(paas.ObjectMeta.Annotations, annotationFilters); err != nil {
		logrus.Infof("Skipping %s (annotation selector)", paas.Name)
		return err
	} else if isAnnoFlt {
		return nil
	}
	logrus.Debugf("label selector %s", labelFilters)
	if isLblFlt, err := isFiltered(paas.ObjectMeta.Labels, labelFilters); err != nil {
		logrus.Infof("Skipping %s (label selector)", paas.Name)
		return err
	} else if isLblFlt {
		return nil
	}

	logrus.Infof("Reencrypting %s", paas.Name)
	if err := s.reencryptPaas(paas); err != nil {
		return err
	}
	return object.SetPaas(*paas)
}
