/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

//revive:disable:exported

package v1alpha1

import (
	paasquota "github.com/belastingdienst/opr-paas/v5/pkg/quota"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Definitions to manage status conditions
const (
	// TypeReadyPaas represents the status of the Paas reconciliation
	TypeReadyPaas = "Ready"
	// TypeHasErrorsPaas represents the status used when the Paas reconciliation holds errors.
	TypeHasErrorsPaas = "HasErrors"
	// revive:disable-next-line
	// TypeDegradedPaas represents the status used when the Paas is deleted
	// and the finalizer operations are yet to occur.
	TypeDegradedPaas = "Degraded"
)

// PaasSpec defines the desired state of Paas
type PaasSpec struct {
	// Capabilities is a subset of capabilities that will be available in this Paas Project
	// +kubebuilder:validation:Optional
	Capabilities PaasCapabilities `json:"capabilities"`

	// Requestor is an informational field which decides on the requestor (also application responsible)
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Required
	Requestor string `json:"requestor"`

	// Groups define k8s groups, based on an LDAP query or a list of LDAP users, which get access to the namespaces
	// belonging to this Paas. Per group, RBAC roles can be defined.
	// +kubebuilder:validation:Optional
	Groups PaasGroups `json:"groups"`

	// Quota defines the quotas which should be set on the cluster resource quota as used by this Paas project
	// +kubebuilder:validation:Required
	Quota paasquota.Quota `json:"quota"`

	// Namespaces can be used to define extra namespaces to be created as part of this Paas project
	// As the names are used as the names of PaasNs resources, they must comply to the DNS subdomainname regex
	// See https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#dns-subdomain-names for more info
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([a-z0-9-]{0,251}[a-z0-9])?$`
	Namespaces []string `json:"namespaces"`
	// You can add ssh keys (which is a type of secret) for ArgoCD to use for access to bitBucket.
	// They must be encrypted with a public key, for which the private key should be added to the DecryptKeySecret
	// +kubebuilder:validation:Optional
	SSHSecrets map[string]string `json:"sshSecrets"`

	// Indicated by which 3rd party Paas's ArgoCD this Paas is managed
	// +kubebuilder:validation:Optional
	ManagedByPaas string `json:"managedByPaas"`
}

// PaasGroup can hold information about a group in the paas.spec.groups block
type PaasGroup struct {
	// A fully qualified LDAP query which will be used by the Group Sync Operator to sync users to the defined group.
	//
	// When set in combination with `users`, the Group Sync Operator will overwrite the manually assigned users.
	// Therefore, this field is mutually exclusive with `group.users`.
	// +kubebuilder:validation:Optional
	Query string `json:"query"`
	// A list of LDAP users which are added to the defined group.
	//
	// When set in combination with `users`, the Group Sync Operator will overwrite the manually assigned users.
	// Therefore, this field is mutually exclusive with `group.query`.
	// +kubebuilder:validation:Optional
	Users []string `json:"users"`
	// List of roles, as defined in the `PaasConfig` which the users in this group get assigned via a rolebinding.
	// +kubebuilder:validation:Optional
	Roles []string `json:"roles"`
}

// PaasGroups hold all groups in a paas.spec.groups
type PaasGroups map[string]PaasGroup

// PaasCapabilities holds all capabilities enabled in a Paas
type PaasCapabilities map[string]PaasCapability

// PaasCapability holds all information for a capability
type PaasCapability struct {
	// Do we want to use this capability, default false
	// +kubebuilder:validation:Optional
	Enabled bool `json:"enabled"`
	// The URL that contains the Applications / Application Sets to be used by this capability
	// +kubebuilder:validation:Optional
	GitURL string `json:"gitUrl"`
	// The revision of the git repo that contains the Applications / Application Sets to be used by this capability
	// +kubebuilder:validation:Optional
	GitRevision string `json:"gitRevision"`
	// the path in the git repo that contains the Applications / Application Sets to be used by this capability
	// +kubebuilder:validation:Optional
	GitPath string `json:"gitPath"`
	// Custom fields to configure this specific Capability
	// +kubebuilder:validation:Optional
	CustomFields map[string]string `json:"custom_fields"`
	// This project has its own ClusterResourceQuota settings
	// +kubebuilder:validation:Optional
	Quota paasquota.Quota `json:"quota"`
	// You can add ssh keys (which is a type of secret) for capability to use for access to bitBucket
	// They must be encrypted with a public key, for which the private key should be added to the DecryptKeySecret
	// +kubebuilder:validation:Optional
	SSHSecrets map[string]string `json:"sshSecrets"`
	// You can enable extra permissions for the service accounts belonging to this capability
	// Exact definitions is configured in Paas Configmap
	// +kubebuilder:validation:Optional
	ExtraPermissions bool `json:"extra_permissions"`
}

// revive:disable:line-length-limit

// PaasStatus defines the observed state of Paas
type PaasStatus struct {
	// Deprecated: use paasns.status.conditions instead
	// +kubebuilder:validation:Optional
	Messages []string `json:"messages"`
	// Deprecated: will not be set and removed in a future release
	// +kubebuilder:validation:Optional
	Quota map[string]paasquota.Quota `json:"quotas"`
	// +kubebuilder:validation:Optional
	Conditions []metav1.Condition `json:"conditions" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
}

// revive:enable:line-length-limit

// Paas is the Schema for the paas API
type Paas struct {
	metav1.TypeMeta   `json:""`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PaasSpec   `json:"spec,omitempty"`
	Status PaasStatus `json:"status,omitempty"`
}

// PaasList contains a list of Paas
type PaasList struct {
	metav1.TypeMeta `json:""`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Paas `json:"items,omitempty"`
}
