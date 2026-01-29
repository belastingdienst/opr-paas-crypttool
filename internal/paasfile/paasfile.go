/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package paasfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/belastingdienst/opr-paas/v4/api/v1alpha1"
	"github.com/belastingdienst/opr-paas/v4/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

// FileFormat is the type of the Paas file; json, yaml, unknown
type FileFormat uint

// File formats supported by this package
const (
	FiletypeUnknown FileFormat = iota
	FiletypeJSON
	FiletypeYAML
)

var fileFormatString = map[FileFormat]string{
	FiletypeJSON:    "json",
	FiletypeYAML:    "yaml",
	FiletypeUnknown: "unknown",
}

// Returns a string representation of fileFormat, if known.
func (ff FileFormat) String() string {
	if s, exists := fileFormatString[ff]; exists {
		return s
	}
	return FiletypeUnknown.String()
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

// ReadPaasFile reads a PaaS file and returns the parsed Paas object.
func ReadPaasFile(filePath string) (*v1alpha2.Paas, FileFormat, error) {
	var paas v1alpha2.Paas
	var buffer []byte

	// Check which API version we're dealing with
	version, err := ApiVersion(filePath)
	if err != nil {
		logrus.Debugf("error reading file %s: %s", filePath, err)
		return nil, FiletypeUnknown, err
	}

	// Read in either a v1alpha1 when needed
	if version == "cpet.belastingdienst.nl/v1alpha1" {
		return ReadV1PaasFile(filePath)
	}

	// It's a v1alpha2, continue
	buffer, err = ReadFile(filePath)
	if err != nil {
		return nil, FiletypeUnknown, err
	}

	// Is it a JSON?
	err = json.Unmarshal(buffer, &paas)
	if err == nil {
		return &paas, FiletypeJSON, nil
	}
	logrus.Debugf("could not parse %s as json, perhaps its a yaml file: %e", filePath, err)

	// Is it a YAML?
	err = yaml.Unmarshal(buffer, &paas)
	if err == nil {
		return &paas, FiletypeYAML, nil
	}
	logrus.Debugf("could not parse %s as yaml: %e", filePath, err)

	// Dunno what the hell it is...
	return nil, FiletypeUnknown, &InvalidPaasFileFormat{File: filePath}
}

// ReadV1PaasFile reads a v1alpha1 Paas file, converts it to a v1alpha2 Paas and
// returns the parsed Paas object.
func ReadV1PaasFile(filePath string) (*v1alpha2.Paas, FileFormat, error) {
	var paas v1alpha1.Paas
	var buffer []byte

	// It's a v1alpha1 apparently
	buffer, err := ReadFile(filePath)
	if err != nil {
		return nil, FiletypeUnknown, err
	}

	// Is it a JSON?
	err = json.Unmarshal(buffer, &paas)
	if err == nil {
		return convertFromV1alpha1(paas), FiletypeJSON, nil
	}
	logrus.Debugf("could not parse %s as json, perhaps its a yaml file: %e", filePath, err)

	// Is it a YAML?
	err = yaml.Unmarshal(buffer, &paas)
	if err == nil {
		return convertFromV1alpha1(paas), FiletypeYAML, nil
	}
	logrus.Debugf("could not parse %s as yaml: %e", filePath, err)

	// Dunno what the hell it is...
	return nil, FiletypeUnknown, &InvalidPaasFileFormat{File: filePath}
}

// convert v1alpha1 into v1alpha2
func convertFromV1alpha1(in v1alpha1.Paas) *v1alpha2.Paas {
	var converted = &v1alpha2.Paas{}

	in.ConvertTo(converted)
	converted.APIVersion = "cpet.belastingdienst.nl/v1alpha2"
	converted.Kind = "Paas"

	return converted
}

// WriteFile writes the given file to disk.
func WriteFile(buffer []byte, path string) error {
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

// WriteFormattedFile writes the given paas to disk in a format that can be read by the parser.
func WriteFormattedFile(paas *v1alpha2.Paas, path string, format FileFormat) error {
	var buffer []byte
	var err error

	switch format {
	default:
		return fmt.Errorf("invalid output format: %s", format)
	case FiletypeJSON:
		buffer, err = json.Marshal(&paas)
	case FiletypeYAML:
		buffer, err = yaml.Marshal(&paas)
	}

	if err != nil {
		return err
	}

	return WriteFile(buffer, path)
}

type kubernetesHeader struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
}

// ApiVersion returns the API version of a Kubernetes manifest file.
func ApiVersion(filePath string) (version string, err error) {
	var header kubernetesHeader
	var content []byte

	// Read the file content
	content, err = ReadFile(filePath)
	if err != nil {
		return "", err
	}

	// Try YAML unmarshal first
	err = yaml.Unmarshal(content, &header)
	if err != nil {
		// If YAML fails, try JSON as fallback
		err = json.Unmarshal(content, &header)
		if err != nil {
			return "", &InvalidPaasFileFormat{File: filePath}
		}
	}

	if header.Kind != "Paas" {
		logrus.Debugf("unsupported Kind, got: %s", header.APIVersion)
		return "", fmt.Errorf("unsupported Kind, got: %s", header.APIVersion)
	}

	if header.APIVersion == "" {
		logrus.Debugf("unknown APIVersion, got: %s", header.APIVersion)
		return "", fmt.Errorf("unknown APIVersion, got: %s", header.APIVersion)
	}

	return header.APIVersion, nil
}

// ReadFile reads a file and returns its content.
func ReadFile(file string) (content []byte, err error) {
	logrus.Debugf("loading %s", file)
	content, err = os.ReadFile(file)
	if err != nil {
		logrus.Debugf("could not read %s: %e", file, err)
		return nil, err
	}

	if len(content) == 0 {
		return nil, errors.New("empty paas file")
	}

	return content, nil
}
