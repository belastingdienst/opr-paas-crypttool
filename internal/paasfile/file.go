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

	"github.com/belastingdienst/opr-paas-cli/v2/internal/stubs/opr-paas/v1alpha1"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/yaml"
)

// InvalidPaasFileFormat represents an error when the PaaS file format is invalid.
type InvalidPaasFileFormat struct {
	// File causing the error.
	File string
}

// Returns an error message indicating that the file is not in a supported format.
func (ip *InvalidPaasFileFormat) Error() string {
	return fmt.Sprintf("file '%s' is not in a supported file format", ip.File)
}

// File represents a file with a Paas resource definition
type File struct {
	Path    string
	Format  Format
	header  *Header
	content []byte
	paas    *v1alpha2.Paas
}

// GetContent reads a file and returns its content.
func (f *File) GetContent() (content []byte, err error) {
	if f.content != nil {
		return f.content, nil
	}

	logrus.Debugf("loading %s", f.Path)

	content, err = os.ReadFile(f.Path)
	if err != nil {
		logrus.Debugf("could not read %s: %e", f.Path, err)
		return nil, err
	}

	if len(content) == 0 {
		return nil, errors.New("empty paas file")
	}

	f.content = content
	return content, nil
}

// SetContent sets the internal content value, and resets the Paas pointer
func (f *File) SetContent(content []byte) {
	f.content = content
	f.paas = nil
}

// GetHeader returns the k8s header of a Kubernetes resource from a file.
func (f *File) GetHeader() (header *Header, err error) {
	if f.header != nil {
		return f.header, nil
	}
	content, err := f.GetContent()
	if err != nil {
		return nil, err
	}
	// Try YAML unmarshal (superset of JSON, so also works for JSON)
	err = yaml.Unmarshal(content, &header)
	if err != nil {
		return nil, &InvalidPaasFileFormat{File: f.Path}
	}
	f.header = header
	return header, nil
}

// GetPaas parses content using multiple conversion functions and
// returns v1alpha2.Paas or a list of errors
func (f *File) GetPaas() (paas *v1alpha2.Paas, err error) {
	_, err = f.GetHeader()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, getPaasFunc := range []func() (*v1alpha2.Paas, error){
		f.readPaasv1File,
		f.readPaasv2File,
	} {
		paas, err := getPaasFunc()
		if err == nil {
			return paas, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("failed to parse file:\n%w", errors.Join(errs...))
}

// SetPaas sets the Paas pointer, and additionally sets the Contents value
func (f *File) SetPaas(paas v1alpha2.Paas) {
	f.paas = &paas
	content, err := f.getContentFromPaas(AutoFormat)
	if err != nil {
		f.content = content
	} else {
		f.content = nil
	}
}

// ReadPaasFile reads a PaaS file and returns the parsed Paas object.
func (f *File) readPaasv2File() (*v1alpha2.Paas, error) {
	var header *Header
	var err error

	// Check which API header we're dealing with
	header, err = f.GetHeader()
	if err != nil {
		logrus.Debugf("error reading file %s: %s", f.Path, err)
		return nil, err
	}
	if err = f.header.Verify(); err != nil {
		return nil, err
	}
	if header.APIVersion != V2Version {
		err = fmt.Errorf("invalid version ('%s' != '%s')", header.APIVersion, V1Version)
		logrus.Debug(err)
		return nil, err
	}

	// It's a v1alpha2, continue
	var content []byte
	content, err = f.GetContent()
	if err != nil {
		return nil, err
	}

	// Is it a JSON?
	var paas v1alpha2.Paas
	err = json.Unmarshal(content, &paas)
	if err == nil {
		f.Format = JSONFormat
		f.paas = &paas
		return &paas, nil
	}
	logrus.Debugf("could not parse %s as json, perhaps its a yaml file: %e", f.Path, err)

	// Is it a YAML?
	err = yaml.Unmarshal(content, &paas)
	if err == nil {
		f.Format = YAMLFormat
		f.paas = &paas
		return &paas, nil
	}
	logrus.Debugf("could not parse %s as yaml: %e", f.Path, err)

	// Dunno what the hell it is...
	return nil, &InvalidPaasFileFormat{File: f.Path}
}

// ReadV1PaasFile reads a v1alpha1 Paas file, converts it to a v1alpha2 Paas and
// returns the parsed Paas object.
func (f *File) readPaasv1File() (*v1alpha2.Paas, error) {
	var err error
	var header *Header
	// Check which API header we're dealing with
	header, err = f.GetHeader()
	if err != nil {
		logrus.Debugf("error reading file %s: %s", f.Path, err)
		return nil, err
	}
	if err = f.header.Verify(); err != nil {
		return nil, err
	}
	if header.APIVersion != V1Version {
		err = fmt.Errorf("invalid version ('%s' != '%s')", header.APIVersion, V2Version)
		logrus.Debug(err)
		return nil, err
	}

	// It's a v1alpha2, continue
	var content []byte
	content, err = f.GetContent()
	if err != nil {
		return nil, err
	}

	var paas v1alpha1.Paas
	// Only used her, let's inline
	var convertFromV1alpha1 = func(in v1alpha1.Paas) *v1alpha2.Paas {
		converted := &v1alpha2.Paas{}

		in.ConvertTo(converted)
		converted.APIVersion = V2Version
		converted.Kind = "Paas"

		return converted
	}

	// Is it a JSON?
	err = json.Unmarshal(content, &paas)
	if err == nil {
		f.Format = JSONFormat
		f.paas = convertFromV1alpha1(paas)
		return f.paas, nil
	}
	logrus.Debugf("could not parse %s as json, perhaps its a yaml file: %e", f.Path, err)

	// Is it a YAML?
	err = yaml.Unmarshal(content, &paas)
	if err == nil {
		f.Format = YAMLFormat
		f.paas = convertFromV1alpha1(paas)
		return f.paas, nil
	}
	logrus.Debugf("could not parse %s as yaml: %e", f.Path, err)

	// Dunno what the hell it is...
	return nil, &InvalidPaasFileFormat{File: f.Path}
}

func writeContent(path string, content []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}

	if _, err := file.Write(content); err != nil {
		return err
	}
	logrus.Infof("file '%s' successfully updated", path)
	return nil
}

// WriteContent writes the given file to disk.
func (f File) WriteContent(path string) error {
	content, err := f.GetContent()
	if err != nil {
		return err
	}
	if path == "" {
		path = f.Path
	}
	return writeContent(path, content)
}

func (f File) getContentFromPaas(format Format) ([]byte, error) {
	if format == AutoFormat {
		format = f.Format
	}
	paas, err := f.GetPaas()
	if err != nil {
		return nil, err
	}
	var buffer []byte
	switch format {
	case JSONFormat:
		buffer, err = json.Marshal(paas)
		if err != nil {
			return nil, err
		}
	case YAMLFormat:
		buffer, err = yaml.Marshal(&paas)
		if err != nil {
			return nil, err
		}
		buffer = append([]byte("---\n"), buffer...)
	default:
		return nil, fmt.Errorf("invalid output format: %s", format)
	}
	return buffer, nil
}

// Write writes the given paas to disk in a format that can be read by the parser.
func (f File) Write(path string, format Format) error {
	if path == "" {
		path = f.Path
	}
	buffer, err := f.getContentFromPaas(format)
	if err != nil {
		return err
	}
	return writeContent(path, buffer)
}
