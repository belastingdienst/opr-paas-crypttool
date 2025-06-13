/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/belastingdienst/opr-paas/v2/api/v1alpha1"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

type fileFormat uint

const (
	typeUnknown fileFormat = iota
	typeJSON
	typeYAML
)

var fileFormatString = map[fileFormat]string{
	typeJSON:    "json",
	typeYAML:    "yaml",
	typeUnknown: "unknown",
}

// Returns a string representation of fileFormat, if known.
func (ff fileFormat) String() string {
	if s, exists := fileFormatString[ff]; exists {
		return s
	}
	return typeUnknown.String()
}

// InvalidPaasFileFormat represents an error when the PaaS file format is invalid.
type InvalidPaasFileFormat struct {
	// File causing the error.
	File string
}

// Returns an error message indicating that the file is not in a supported format.
func (ip *InvalidPaasFileFormat) Error() string {
	return fmt.Sprintf("file '%s' is not in a supported file format", ip.File)
}

// readPaasFile reads a PaaS file and returns the parsed Paas object.
func readPaasFile(file string) (*v1alpha1.Paas, fileFormat, error) {
	var paas v1alpha1.Paas

	logrus.Debugf("parsing %s", file)
	buffer, err := os.ReadFile(file)
	if err != nil {
		logrus.Debugf("could not read %s: %e", file, err)
		return nil, typeUnknown, err
	}

	if len(buffer) == 0 {
		return nil, typeUnknown, errors.New("empty paas configuration file")
	}

	err = json.Unmarshal(buffer, &paas)
	if err == nil {
		return &paas, typeJSON, nil
	}
	logrus.Debugf("could not parse %s as json: %e", file, err)

	err = yaml.Unmarshal(buffer, &paas)
	if err == nil {
		return &paas, typeYAML, nil
	}
	logrus.Debugf("could not parse %s as yaml: %e", file, err)

	return nil, typeUnknown, &InvalidPaasFileFormat{File: file}
}

// writeFile writes the given file to disk.
func writeFile(buffer []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	if _, err := file.Write(buffer); err != nil {
		return err
	}

	logrus.Infof("file '%s' successfully updated", path)
	return nil
}

// writeFormattedFile writes the given paas to disk in a format that can be read by the parser.
func writeFormattedFile(paas *v1alpha1.Paas, path string, format fileFormat) error {
	var buffer []byte
	var err error

	switch format {
	default:
		return fmt.Errorf("invalid output format: %s", format)
	case typeJSON:
		buffer, err = json.Marshal(&paas)
	case typeYAML:
		buffer, err = yaml.Marshal(&paas)
	}

	if err != nil {
		return err
	}

	return writeFile(buffer, path)
}

// hashData hashes the given data using SHA-512.
func hashData(original []byte) string {
	sum := sha512.Sum512(original)
	return hex.EncodeToString(sum[:])
}
