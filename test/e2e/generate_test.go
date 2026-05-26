/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

// Tests for: kubectl-paas generate
//
// generate:
//   --privateKeyFile  path to write the RSA private key (PEM).
//   --publicKeyFile   path to write the RSA public key (PEM).
//   Generates a 4096-bit RSA key pair and writes both files.
//   The private key is written with mode 0600.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("generate", func() {
	It("writes both key files", func() {
		dir := GinkgoT().TempDir()
		privFile := filepath.Join(dir, "private.pem")
		pubFile := filepath.Join(dir, "public.pem")

		runCLI("generate", "--privateKeyFile", privFile, "--publicKeyFile", pubFile)

		Expect(privFile).To(BeAnExistingFile())
		Expect(pubFile).To(BeAnExistingFile())
	})

	It("writes valid PEM headers", func() {
		privFile, pubFile := freshKeyPair()

		Expect(readFile(privFile)).To(ContainSubstring("RSA PRIVATE KEY"))
		Expect(readFile(pubFile)).To(ContainSubstring("PUBLIC KEY"))
	})

	It("sets mode 0600 on the private key file", func() {
		privFile, _ := freshKeyPair()

		info, err := os.Stat(privFile)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
	})

	It("fails without --privateKeyFile and --publicKeyFile flags", func() {
		_, err := runCLIExpectFailure("generate")
		Expect(err).To(HaveOccurred(), "generate without key path flags must fail")
	})

	It("outputs k8s secret YAML that can be applied to update the secret in the cluster", func() {
		dir := GinkgoT().TempDir()
		privFile := filepath.Join(dir, "private.pem")
		pubFile := filepath.Join(dir, "public.pem")

		out := runCLI("generate",
			"--privateKeyFile", privFile,
			"--publicKeyFile", pubFile,
			"--outputFormat", "yaml",
		)

		// The command prints "Private/Public key written to ..." before the YAML;
		// extract only the YAML document starting at the first --- separator.
		idx := strings.Index(out, "---\n")
		Expect(idx).To(BeNumerically(">=", 0), "output should contain a YAML document separator")
		yamlOut := out[idx:]

		Expect(yamlOut).To(ContainSubstring("kind: Secret"))
		Expect(yamlOut).To(ContainSubstring(keysSecretName))

		cmd := exec.Command("kubectl", "--kubeconfig", kubecfg, "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(yamlOut)
		applyOut, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred(), "kubectl apply: %s", string(applyOut))

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, client.ObjectKey{Name: keysSecretName, Namespace: e2eNamespace}, &secret)).
			To(Succeed())
		Expect(secret.Data).NotTo(BeEmpty(), "secret should contain the generated key after apply")
	})
})
