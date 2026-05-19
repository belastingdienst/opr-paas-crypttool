package paasobject

import (
	"context"
	"errors"

	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
)

// Objects is a collection of Objects that can contain a Paas Object
type Objects []Object

// Object is an interface, so that both a file with yaml, as well as something read from stdin or k8s can be processed
// in a similar way
type Object interface {
	GetPaas() (paas *v1alpha2.Paas, err error)
	SetPaas(newPaas v1alpha2.Paas) error
	Write(context.Context) error
}

func (os Objects) Write(ctx context.Context) error {
	var errs []error
	for _, o := range os {
		err := o.Write(ctx)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
