/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasfile"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/plugin"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/reencrypt"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/utils"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// EncryptCommand returns the cobra Command to run the encryption operation.
func encryptCmd() *cobra.Command {
	var (
		privateKeyFileGlob   string
		publicKeyFile        string
		dataFile             string
		paasName             string
		encryptionSecretName string
		secretName           string
		capabilityName       string
		outputFormat         string
	)

	cmd := &cobra.Command{
		Use:   "encrypt [command options]",
		Short: "encrypt using public key and print results",
		Long:  `encrypt using public key and print results`,
		//revive:disable-next-line
		RunE: func(command *cobra.Command, args []string) error {
			var (
				conversionService reencrypt.ConversionService
				err               error
				data              []byte
			)
			if paasName == "" {
				return errors.New("a paas must be set with eith --paas or environment variabele PAAS_NAME")
			}
			format, err := paasfile.FormatFromString(outputFormat)
			if err != nil {
				return err
			}
			if len(publicKeyFile) > 0 || len(privateKeyFileGlob) > 0 {
				var privateKeyFiles []string
				privateKeyFiles, err = utils.PathToFileList([]string{privateKeyFileGlob})
				if err != nil {
					return err
				}
				conversionService = reencrypt.ConversionService{
					Factory: &reencrypt.FileCryptFactory{
						PrivateKeyFiles: privateKeyFiles,
						PublicKeyFile:   publicKeyFile,
					},
				}
			} else {
				keys, err := keysFromK8s(command.Context(), encryptionSecretName)
				if err != nil {
					return err
				}
				conversionService = reencrypt.ConversionService{
					Factory: &reencrypt.KeyCryptFactory{
						Keys: keys,
					},
				}
			}
			if dataFile == "" {
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return err
				}
			} else {
				data, err = os.ReadFile(dataFile)
				if err != nil {
					return err
				}
			}
			crypter, err := conversionService.Factory.GetCrypt(paasName)
			if err != nil {
				return err
			}
			encrypted, err := crypter.Encrypt(data)
			if err != nil {
				return err
			}
			switch format {
			case paasfile.RawFormat:
				fmt.Print(encrypted)
			case paasfile.JSONFormat, paasfile.YAMLFormat:
				paas, err := plugin.GetPaas(command.Context(), paasName)
				if err != nil {
					return err
				}
				if capabilityName != "" {
					cap, exists := paas.Spec.Capabilities[capabilityName]
					if !exists {
						return fmt.Errorf("paas %s has no capability %s", paasName, capabilityName)
					}
					if cap.Secrets == nil {
						cap.Secrets = map[string]string{}
					}
					cap.Secrets[secretName] = encrypted
				} else {
					if paas.Spec.Secrets == nil {
						paas.Spec.Secrets = map[string]string{}
					}
					paas.Spec.Secrets[secretName] = encrypted
				}
				paas.APIVersion = v1alpha2.GroupVersion.String()
				paas.Kind = "Paas"

				plugin.Print(paas, format, os.Stdout)

			default:
				return fmt.Errorf("Cannot use --outputFormat %s, only (%s, %s, and %s)", format, paasfile.RawFormat,
					paasfile.JSONFormat, paasfile.YAMLFormat)
			}
			return nil

		},
		Example: `kubectl-paas encrypt --publicKeyFile "/tmp/pub" --dataFile "/tmp/decrypted" --paas my-paas`,
	}

	flags := cmd.Flags()
	flags.StringVarP(&privateKeyFileGlob, argNamePrivateKeyFiles, "p", "", "The file to read the private key from")
	flags.StringVar(&publicKeyFile, argNamePublicKeyFile, "", "The file to read the public key from")
	flags.StringVar(&dataFile, argNameDataFileKey, "", "The file to read the data to be encrypted from")
	flags.StringVarP(&outputFormat, argNameOutputFormat, "o", "raw",
		"The output format (raw for string, yaml or json for paas)")
	flags.StringVar(&paasName, argNamePaas, "", "The paas this data is to be encrypted for")
	flags.StringVar(&secretName, argNameSecretName, "",
		"The name of the secret in teh paas to set (when output = yaml or json)")
	flags.StringVar(&capabilityName, argNameCapabilityName, "", "The capability (when output = yaml or json)")

	for envVar, arg := range map[string]string{
		"PAAS_PRIVATE_KEY_PATH": argNamePrivateKeyFiles,
		"PAAS_PUBLIC_KEY_PATH":  argNamePublicKeyFile,
		"PAAS_INPUT_FILE":       argNameDataFileKey,
		"PAAS_FORMAT":           argNameOutputFormat,
		"PAAS_NAME":             argNamePaas,
		"PAAS_SECRET_NAME":      argNameSecretName,
		"PAAS_CAPABILITY_NAME":  argNameCapabilityName,
	} {
		if err := viper.BindPFlag(arg, flags.Lookup(arg)); err != nil {
			logrus.Errorf("key binding for %s failed: %v", arg, err)
		}
		if err := viper.BindEnv(arg, envVar); err != nil {
			logrus.Errorf("paas binding failed for %s: %v", arg, err)
		}
	}
	return cmd
}
