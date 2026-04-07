package paasfile

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	// V1Version is the APIVersion for v1alpha1
	V1Version = "cpet.belastingdienst.nl/v1alpha1"
	// V2Version is the APIVersion for v1alpha2
	V2Version = "cpet.belastingdienst.nl/v1alpha2"
)

var validVersions = map[string]bool{
	V1Version: true,
	V2Version: true,
}

// Header can be used to get K8s info without knowing the exact type
type Header struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
}

// Verify verifies the header to be a valid Paas header
func (h Header) Verify() error {
	if strings.ToLower(h.Kind) != "paas" {
		logrus.Debugf("unsupported Kind, got: %s", h.Kind)
		return fmt.Errorf("unsupported Kind, got: %s", h.Kind)
	}
	if _, exists := validVersions[strings.ToLower(h.APIVersion)]; !exists {
		logrus.Debugf("unknown APIVersion, got: %s", h.APIVersion)
		return fmt.Errorf("unknown APIVersion, got: %s", h.APIVersion)
	}
	return nil
}
