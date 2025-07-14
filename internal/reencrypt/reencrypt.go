/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/belastingdienst/opr-paas-crypttool/internal/paasfile"
	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/sirupsen/logrus"
)

// reencryptSecret decrypts and then re-encrypts a given secret using the provided
// source and destination crypt.Crypt instances.
func reencryptSecret(srcCrypt *crypt.Crypt, dstCrypt *crypt.Crypt, secret string) (string, error) {
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

// Files reencrypts the secrets of given PAAS files using the provided private
// and public keys.
//
// The function iterates over each file, reads its contents, decrypts and reencrypts
// the SSH secrets for each capability, and then writes the updated contents back
// to the original file in the specified output format (JSON or YAML).
func Files(privateKeyFiles string, publicKeyFile string, outputFormat string, files []string) (err error) {
	var errNum int

	for _, fileName := range files {
		errNum, err = reencryptFile(fileName, privateKeyFiles, publicKeyFile, outputFormat)

		if err != nil {
			return err
		}
	}

	errMsg := fmt.Errorf("finished with %d errors", errNum)
	if errNum > 0 {
		return errMsg
	}

	logrus.Info(errMsg)

	return nil
}

//revive:disable-next-line
func reencryptFile(fileName string, privateKeyFiles string, publicKeyFile string, outputFormat string) (errnum int, err error) {
	var errNum int

	// Read paas as String to preserve format
	paasAsBytes, err := os.ReadFile(fileName)
	paasAsString := string(paasAsBytes)
	if err != nil {
		return 0, errors.New("could not read file into string")
	}

	// Read paas from file
	paas, format, err := paasfile.ReadPaasFile(fileName)
	if err != nil {
		return 0, errors.New("could not read file")
	}

	paasName := paas.Name
	srcCrypt, err := crypt.NewCryptFromFiles([]string{privateKeyFiles}, "", paasName)
	if err != nil {
		return 0, err
	}

	dstCrypt, err := crypt.NewCryptFromFiles([]string{}, publicKeyFile, paasName)
	if err != nil {
		return 0, err
	}

	for key, secret := range paas.Spec.Secrets {
		reencrypted, err := reencryptSecret(srcCrypt, dstCrypt, secret)
		if err != nil {
			errNum++
			logrus.Errorf(
				"failed to decrypt/reencrypt %s.spec.Secrets[%s] in %s: %v",
				paasName,
				key,
				fileName,
				err,
			)
			continue
		}

		paas.Spec.Secrets[key] = reencrypted
		// Use replaceAll as same secret can occur multiple times and use TrimSpace to prevent removal of newlines.
		paasAsString = strings.ReplaceAll(paasAsString, strings.TrimSpace(secret), reencrypted)
		logrus.Infof("successfully reencrypted %s.spec.Secrets[%s] in file %s", paasName, key, fileName)
	}

	for capName, cap := range paas.Spec.Capabilities {
		for key, secret := range cap.Secrets {
			reencrypted, err := reencryptSecret(srcCrypt, dstCrypt, secret)
			if err != nil {
				errNum++
				logrus.Errorf(
					"failed to decrypt/reencrypt %s.spec.capabilities.%s.Secrets[%s] in %s: %v",
					paasName,
					capName,
					key,
					fileName,
					err,
				)
				continue
			}

			cap.Secrets[key] = reencrypted
			// Use replaceAll as same secret can occur multiple times
			// Use TrimSpace to prevent removal of newlines.
			paasAsString = strings.ReplaceAll(paasAsString, strings.TrimSpace(secret), reencrypted)
			logrus.Infof(
				"successfully reencrypted %s.spec.capabilities[%s].Secrets[%s] in file %s",
				paasName,
				capName,
				key,
				fileName,
			)
		}
	}

	// Write paas to file
	// TODO: add unit tests for this
	switch outputFormat {
	case "json":
		format = paasfile.FiletypeJSON
	case "yaml":
		format = paasfile.FiletypeYAML
	}

	if outputFormat == "preserved" {
		err := paasfile.WriteFile([]byte(paasAsString), fileName)
		if err != nil {
			return 0, err
		}
	} else {
		err := paasfile.WriteFormattedFile(paas, fileName, format)
		if err != nil {
			return 0, err
		}
	}

	return errNum, nil
}
