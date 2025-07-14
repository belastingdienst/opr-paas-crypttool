/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"fmt"

	"github.com/belastingdienst/opr-paas-crypttool/internal/paasfile"
	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v3/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// checkPaasCmd returns a Cobra command that checks secrets in paas yaml files.
func checkPaasCmd() *cobra.Command {
	var privateKeyFiles string

	cmd := &cobra.Command{
		Use:   "check-paas [command options]",
		Short: "check secrets in paas yaml files",
		Long:  `parse yaml/json files with paas objects, decrypt the Secrets and display length & checksum.`,
		RunE: func(command *cobra.Command, args []string) error {
			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}

			files, err := utils.PathToFileList(args)
			if err != nil {
				return err
			}

			return checkPaasFiles(privateKeyFiles, files)
		},
		Args:    cobra.MinimumNArgs(1),
		Example: `crypttool check-paas --privateKeyFiles "/tmp/priv" [file or dir] ([file or dir]...)`,
	}

	flags := cmd.Flags()
	flags.StringVar(&privateKeyFiles, argNamePrivateKeyFiles, "", "The file or folder containing the private key(s)")

	if err := viper.BindPFlag(argNamePrivateKeyFiles, flags.Lookup(argNamePrivateKeyFiles)); err != nil {
		logrus.Errorf("key binding for private key failed: %v", err)
	}

	if err := viper.BindEnv(argNamePrivateKeyFiles, "PAAS_PRIVATE_KEY_PATH"); err != nil {
		logrus.Errorf("key binding for PAAS_PRIVATE_KEY_PATH failed: %v", err)
	}

	return cmd
}

// checkPaasFiles checks the files specified in 'files' for valid Paas configuration.
//
// It reads each file, extracts its Paas configuration and uses it to decrypt SSH
// secrets and capabilities.
//
// If an error occurs during decryption, an error message is logged and the function
// returns the accumulated number of errors.
func checkPaasFiles(privateKeyFiles string, files []string) error {
	var errNum int
	var paas *v1alpha2.Paas

	for _, fileName := range files {
		version, err := paasfile.ApiVersion(fileName)
		if err != nil {
			return fmt.Errorf("unsupported Paas API version: %s", version)
		}

		// Read paas from file
		if version == "cpet.belastingdienst.nl/v1alpha1" {
			paas, _, err = paasfile.ReadV1PaasFile(fileName)
		} else {
			paas, _, err = paasfile.ReadPaasFile(fileName)
		}

		if err != nil {
			return fmt.Errorf("could not read file %s: %s", fileName, err.Error())
		}

		paasName := paas.Name
		srcCrypt, err := crypt.NewCryptFromFiles([]string{privateKeyFiles}, "", paasName)
		if err != nil {
			return err
		}

		for key, secret := range paas.Spec.Secrets {
			if decrypted, decryptErr := srcCrypt.Decrypt(secret); decryptErr != nil {
				errNum++
				logrus.Errorf("%s: { .spec.Secrets[%s] } > { error: %e }", fileName, key, decryptErr)
			} else {
				logrus.Infof("%s: { .spec.Secrets[%s] } > { checksum: %s, len %d }",
					fileName,
					key,
					utils.HashData(decrypted),
					len(decrypted),
				)
			}
		}

		for capName, capability := range paas.Spec.Capabilities {
			logrus.Debugf("capability name: %s", capName)
			for key, secret := range capability.Secrets {
				if decrypted, decryptErr := srcCrypt.Decrypt(secret); decryptErr != nil {
					logrus.Errorf(
						"%s: { .spec.capabilities[%s].Secrets[%s] } > { error: %e }",
						fileName,
						capName,
						key,
						decryptErr,
					)
					errNum++
				} else {
					logrus.Infof("%s: { .spec.capabilities[%s].Secrets[%s] } > { checksum: %s, len %d }",
						fileName,
						capName,
						key,
						utils.HashData(decrypted),
						len(decrypted),
					)
				}
			}
		}
	}

	errMsg := fmt.Errorf("finished with %d errors", errNum)
	if errNum > 0 {
		logrus.Error(errMsg)
		return errMsg
	}

	logrus.Info(errMsg)

	return nil
}
