package v1alpha1

// PaasConfigTypeValidations can have custom validations for a specific CRD (e.a. paas, paasConfig or PaasNs).
// Refer to https://belastingdienst.github.io/opr-paas/latest/administrators-guide/validations/ for more info.
type PaasConfigTypeValidations map[string]string

// PaasConfigValidations is a map which holds all validations,
// with key being the (lower case) name of the crd and value being a PaasConfigTypeValidations object.
type PaasConfigValidations map[string]PaasConfigTypeValidations
