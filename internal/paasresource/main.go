package paasresource

import (
	"context"
	"errors"

	"github.com/belastingdienst/opr-paas-cli/v2/internal/paasobject"
	"github.com/belastingdienst/opr-paas-cli/v2/internal/plugin"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
)

// Resource defines a Paas as read from k8s
type Resource struct {
	paas *v1alpha2.Paas
}

func (rs Resource) GetPaas() (paas *v1alpha2.Paas, err error) {
	if rs.paas == nil {
		return nil, errors.New("resource has no paas set")
	}
	return paas, nil
}

func (rs *Resource) SetPaas(newPaas v1alpha2.Paas) error {
	rs.paas = &newPaas
	return nil
}

func (rs Resource) Write(ctx context.Context) error {
	// We should probably update more in the future, but a full update without any checks is to brute force.
	// Let's refine this as we add more functionalities to paas-cli
	return plugin.UpdatePaasSecrets(ctx, rs.paas)
}

// FilesFromPaths can be used to collect files from one or more paths
func ResourcesFromK8s(ctx context.Context) (paasobject.Objects, error) {
	var resources = paasobject.Objects{}
	paases, err := plugin.GetPaases(ctx)
	if err != nil {
		return nil, err
	}
	for _, paas := range paases {
		resources = append(resources, &Resource{paas: &paas})
	}
	return resources, nil
}
