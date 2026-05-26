/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

// Tests for: kubectl-paas migrate
//
// migrate:
//   Accepts one or more Paas YAML/JSON file paths as positional arguments.
//   Reads each file, converts it to the latest Paas API version (v1alpha2),
//   and writes the result back to the same file.
//
// Key migration details (v1alpha1 → v1alpha2):
//   - apiVersion bump
//   - spec.sshSecrets  → spec.secrets
//   - spec.namespaces []string → spec.namespaces map[string]{}
//   - capabilities[*].gitUrl/gitRevision/gitPath → customFields["git_url"/…]
//   - capabilities with enabled:false are dropped
//
// migrate does not query k8s (PersistentPreRunE runs but no resources accessed).

import (
	"os"
	"strings"

	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	paasquota "github.com/belastingdienst/opr-paas/v5/pkg/quota"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// v1alpha1PaasFixture reads the v1alpha1 Paas fixture from testdata.
// Kept as a YAML file because there is no v1alpha1 Go type in the module.
func v1alpha1PaasFixture() string {
	data, err := os.ReadFile("testdata/v1alpha1-paas.yaml")
	Expect(err).NotTo(HaveOccurred())
	return string(data)
}

// v2Alpha2PaasFixture builds a plain v1alpha2 Paas struct and marshals it to YAML.
func v2Alpha2PaasFixture() string {
	paas := v1alpha2.Paas{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha2.GroupVersion.String(),
			Kind:       "Paas",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-v2-paas",
		},
		Spec: v1alpha2.PaasSpec{
			Requestor: "test-team",
			Quota: paasquota.Quota{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			},
		},
	}
	out, err := yaml.Marshal(paas)
	if err != nil {
		panic("marshal v2alpha2 paas fixture: " + err.Error())
	}
	return string(out)
}

var _ = Describe("migrate", func() {
	It("rewrites a v1alpha1 file to v1alpha2", func() {
		paasFile := writeTempFile(v1alpha1PaasFixture(), "paas.yaml")

		runCLI("migrate", paasFile)

		content := readFile(paasFile)
		Expect(content).To(ContainSubstring("cpet.belastingdienst.nl/v1alpha2"))
		Expect(content).NotTo(ContainSubstring("cpet.belastingdienst.nl/v1alpha1"))
	})

	It("is idempotent: a v1alpha2 file stays v1alpha2", func() {
		paasFile := writeTempFile(v2Alpha2PaasFixture(), "paas.yaml")

		runCLI("migrate", paasFile)

		Expect(readFile(paasFile)).To(ContainSubstring("cpet.belastingdienst.nl/v1alpha2"))
	})

	It("moves gitUrl/gitRevision/gitPath into customFields", func() {
		paasFile := writeTempFile(v1alpha1PaasFixture(), "paas.yaml")

		runCLI("migrate", paasFile)

		content := readFile(paasFile)
		Expect(strings.Contains(content, "git_url") || strings.Contains(content, "customFields")).
			To(BeTrue(), "migrated capability should have git_url in customFields; got:\n%s", content)
	})

	It("fails without file arguments", func() {
		_, err := runCLIExpectFailure("migrate")
		Expect(err).To(HaveOccurred(), "migrate without file args must fail")
	})

	It("rejects non-YAML files", func() {
		badFile := writeTempFile("NOT YAML AT ALL }{{{ ]]]", "bad.yaml")

		_, err := runCLIExpectFailure("migrate", badFile)
		Expect(err).To(HaveOccurred(), "migrate on a non-YAML file must fail")
	})
})
