/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"errors"

	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// generateCmd generates a new private and public key pair and stores them in the
// specified files.
func generateCmd() *cobra.Command {
	var publicKeyFile string
	var privateKeyFile string

	cmd := &cobra.Command{
		Use:   "generate [command options]",
		Short: "generate a new private and public key and store them in files",
		Long:  `generate a new private and public key and store them in files`,
		//revive:disable-next-line
		RunE: func(command *cobra.Command, args []string) error {
			if privateKeyFile == "" || publicKeyFile == "" {
				return errors.New("privateKeyFile of publicKeyFile not specified")
			}
			return crypt.GenerateKeyPair(privateKeyFile, publicKeyFile)
		},
		Example: `crypttool generate --publicKeyFile "/tmp/pub" --privateKeyFile "/tmp/priv"`,
	}

	flags := cmd.Flags()
	flags.StringVar(&publicKeyFile, argNamePublicKeyFile, "", "The file to write the public key to")
	flags.StringVar(&privateKeyFile, argNamePrivateKeyFile, "", "The file to write the private key to")

	if err := viper.BindPFlag(argNamePublicKeyFile, flags.Lookup(argNamePublicKeyFile)); err != nil {
		logrus.Errorf("key binding for publicKeyFile failed: %v", err)
	}
	if err := viper.BindPFlag(argNamePrivateKeyFile, flags.Lookup(argNamePrivateKeyFile)); err != nil {
		logrus.Errorf("key binding for privateKeyFile failed: %v", err)
	}
	if err := viper.BindEnv(argNamePublicKeyFile, "PAAS_PUBLIC_KEY_PATH"); err != nil {
		logrus.Errorf("paas public key binding failed: %v", err)
	}
	if err := viper.BindEnv(argNamePrivateKeyFile, "PAAS_PRIVATE_KEY_PATH"); err != nil {
		logrus.Errorf("paas private key binding failed: %v", err)
	}

	return cmd
}
