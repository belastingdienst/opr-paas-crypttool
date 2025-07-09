/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"github.com/belastingdienst/opr-paas-crypttool/internal/reencrypt"
	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func reencryptCmd() *cobra.Command {
	var privateKeyFiles string
	var publicKeyFile string
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "reencrypt [command options]",
		Short: "reencrypt using old private key to decrypt and new public key to encrypt",
		//revive:disable-next-line
		Long: `parse yaml/json files with paas objects, decrypt the Secrets with the previous private key,
reencrypt with the new public key and write the Paas back to the file in either yaml or json format.`,
		//revive:disable-next-line
		RunE: func(command *cobra.Command, args []string) error {
			var files []string
			var err error

			if debug {
				logrus.SetLevel(logrus.DebugLevel)
			}

			if files, err = utils.PathToFileList(args); err != nil {
				return err
			}

			return reencrypt.Files(privateKeyFiles, publicKeyFile, outputFormat, files)
		},
		Args: cobra.MinimumNArgs(1),
		//revive:disable-next-line
		Example: `crypttool reencrypt --privateKeyFiles "/tmp/priv" --publicKeyFile "/tmp/pub" [file or dir] ([file or dir]...)`,
	}

	flags := cmd.Flags()
	flags.StringVar(&privateKeyFiles, "privateKeyFiles", "", "The file to read the private key from")
	flags.StringVar(&publicKeyFile, "publicKeyFile", "", "The file to read the public key from")
	flags.StringVar(
		&outputFormat,
		argNameOutputFormat,
		"auto",
		//revive:disable-next-line
		"The outputformat for writing a Paas, either yaml (machine formatted), json (machine formatted), auto (which will use input format as output, machine formatted) or preserved (which will use the input format and preserve the original syntax including for example comments) ",
	)

	if err := viper.BindPFlag(argNamePrivateKeyFiles, flags.Lookup(argNamePrivateKeyFiles)); err != nil {
		logrus.Errorf("key binding for privatekeyfiles failed: %v", err)
	}
	if err := viper.BindPFlag(argNamePublicKeyFile, flags.Lookup(argNamePublicKeyFile)); err != nil {
		logrus.Errorf("key binding for publickeyfile failed: %v", err)
	}
	if err := viper.BindPFlag(argNameOutputFormat, flags.Lookup(argNameOutputFormat)); err != nil {
		logrus.Errorf("key binding at output step failed: %v", err)
	}
	if err := viper.BindEnv(argNamePrivateKeyFiles, "PAAS_PRIVATE_KEY_PATH"); err != nil {
		logrus.Errorf("private key to env var binding failed: %v", err)
	}
	if err := viper.BindEnv(argNamePublicKeyFile, "PAAS_PUBLIC_KEY_PATH"); err != nil {
		logrus.Errorf("public key to env var binding failed: %v", err)
	}
	if err := viper.BindEnv(argNameOutputFormat, "PAAS_OUTPUT_FORMAT"); err != nil {
		logrus.Errorf("key binding at output step failed: %v", err)
	}

	return cmd
}
