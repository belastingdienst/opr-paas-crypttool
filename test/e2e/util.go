/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package e2e

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	paasquota "github.com/belastingdienst/opr-paas/v5/pkg/quota"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"
)

const (
	waitInterval    = 1 * time.Second
	waitTimeout     = 2 * time.Minute
	filePermissions = 0o644
)

// Package-level state set by BeforeSuite.
var (
	kubecfg    string
	cliBinPath string

	k8sClient client.Client
	ctx       context.Context
	cancelCtx context.CancelFunc
)

// deleteResourceSync deletes a k8s resource and polls until it is gone.
func deleteResourceSync(obj client.Object) {
	err := k8sClient.Delete(ctx, obj)
	if err != nil && !apierrors.IsNotFound(err) {
		gomega.Expect(err).NotTo(gomega.HaveOccurred())
	}
	key := client.ObjectKeyFromObject(obj)
	gomega.Eventually(func() bool {
		return apierrors.IsNotFound(k8sClient.Get(ctx, key, obj))
	}).Should(gomega.BeTrue(), "waiting for %s to be deleted", obj.GetName())
}

// createPaasConfig creates a PaasConfig and polls until it is visible in the API.
func createPaasConfig(pc v1alpha2.PaasConfig) {
	gomega.Expect(k8sClient.Create(ctx, &pc)).To(gomega.Succeed())
	gomega.Eventually(func() error {
		var fetched v1alpha2.PaasConfig
		return k8sClient.Get(ctx, client.ObjectKeyFromObject(&pc), &fetched)
	}).Should(gomega.Succeed())
}

// registerSchemes adds corev1 and v1alpha2 types to the given scheme.
func registerSchemes(s *runtime.Scheme) error {
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme,
		v1alpha2.AddToScheme,
	} {
		if err := add(s); err != nil {
			return err
		}
	}
	return nil
}

// writeTempFile writes content to a temp file and returns its path.
// The file is cleaned up automatically at the end of the current spec.
func writeTempFile(content, filename string) string {
	path := filepath.Join(ginkgo.GinkgoT().TempDir(), filename)
	gomega.Expect(os.WriteFile(path, []byte(content), filePermissions)).To(gomega.Succeed())
	return path
}

// readFile returns the contents of a file, failing the test on error.
func readFile(path string) string {
	data, err := os.ReadFile(path)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "read %s", path)
	return string(data)
}

// freshKeyPair generates an RSA key pair via the CLI and returns (privPath, pubPath).
func freshKeyPair() (string, string) {
	dir := ginkgo.GinkgoT().TempDir()
	privFile := filepath.Join(dir, "private.pem")
	pubFile := filepath.Join(dir, "public.pem")
	runCLI("generate", "--privateKeyFile", privFile, "--publicKeyFile", pubFile)
	return privFile, pubFile
}

// encryptWithPubKey encrypts plaintext using only the public key file (no k8s needed).
func encryptWithPubKey(pubFile, paasName, plaintext string) string {
	c, err := crypt.NewCryptFromFiles([]string{}, pubFile, paasName)
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	encrypted, err := c.Encrypt([]byte(plaintext))
	gomega.Expect(err).NotTo(gomega.HaveOccurred())
	return encrypted
}

// runCLI runs kubectl-paas with the given args, failing the test on non-zero exit.
// --kubeconfig is always prepended so the subprocess finds the cluster.
func runCLI(args ...string) string {
	out, err := runCLIRaw(nil, args...)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "kubectl-paas %v\noutput: %s", args, out)
	return out
}

// runCLIWithStdin is like runCLI but pipes stdin into the subprocess.
func runCLIWithStdin(stdin string, args ...string) string {
	out, err := runCLIRaw(strings.NewReader(stdin), args...)
	gomega.Expect(err).NotTo(gomega.HaveOccurred(), "kubectl-paas %v (with stdin)\noutput: %s", args, out)
	return out
}

// runCLIExpectFailure runs the CLI and returns the combined output and the exit error.
// The caller owns all assertions.
func runCLIExpectFailure(args ...string) (string, error) {
	return runCLIRaw(nil, args...)
}

// runCLIRaw is the low-level executor.
func runCLIRaw(stdin io.Reader, args ...string) (string, error) {
	allArgs := append([]string{"--kubeconfig", kubecfg}, args...)
	cmd := exec.Command(cliBinPath, allArgs...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// paasWithSecret builds a v1alpha2.Paas with a single encrypted secret and marshals it to YAML.
func paasWithSecret(paasName, encryptedValue string) string {
	paas := v1alpha2.Paas{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha2.GroupVersion.String(),
			Kind:       "Paas",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: paasName,
		},
		Spec: v1alpha2.PaasSpec{
			Requestor: "test-team",
			Quota: paasquota.Quota{
				corev1.ResourceCPU:    resource.MustParse("4"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			},
			Secrets: map[string]string{
				"mysecret": encryptedValue,
			},
		},
	}
	out, err := yaml.Marshal(paas)
	if err != nil {
		panic("marshal paas fixture: " + err.Error())
	}
	return string(out)
}
