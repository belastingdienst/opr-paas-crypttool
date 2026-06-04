/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"context"
)

const (
	e2eNamespace   = "paas-e2e"
	keysSecretName = "test-keys"
	paasConfigName = "paas-config"
)

var examplePaasConfig = v1alpha2.PaasConfig{
	ObjectMeta: metav1.ObjectMeta{
		Name: paasConfigName,
	},
	Spec: v1alpha2.PaasConfigSpec{
		DecryptKeysSecret: v1alpha2.NamespacedName{
			Name:      keysSecretName,
			Namespace: e2eNamespace,
		},
		ManagedByLabel:  "argocd.argoproj.io/manby",
		ManagedBySuffix: "argocd",
		RequestorLabel:  "o.lbl",
		QuotaLabel:      "q.lbl",
	},
}

func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "kubectl-paas e2e")
}

var _ = BeforeSuite(func() {
	ctx, cancelCtx = context.WithCancel(context.Background())

	SetDefaultEventuallyTimeout(waitTimeout)
	SetDefaultEventuallyPollingInterval(waitInterval)

	// Locate pre-built binary.
	if bin := os.Getenv("KUBECTL_PAAS_BIN"); bin != "" {
		cliBinPath = bin
	} else {
		cliBinPath = filepath.Join("..", "..", "bin", "kubectl-paas")
	}
	if _, err := os.Stat(cliBinPath); err != nil {
		fmt.Fprintf(os.Stderr, "kubectl-paas binary not found at %s — run `make build` first\n", cliBinPath)
		os.Exit(1)
	}

	// Resolve kubeconfig path for --kubeconfig flag passed to subprocess.
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		kubecfg = kc
	} else {
		home, err := os.UserHomeDir()
		Expect(err).NotTo(HaveOccurred())
		kubecfg = filepath.Join(home, ".kube", "config")
	}

	// Build k8s client.
	restCfg, err := ctrl.GetConfig()
	Expect(err).NotTo(HaveOccurred())

	scheme := runtime.NewScheme()
	Expect(registerSchemes(scheme)).To(Succeed())

	k8sClient, err = client.New(restCfg, client.Options{Scheme: scheme})
	Expect(err).NotTo(HaveOccurred())

	// Create namespace (unless the caller provided one via env).
	ns := e2eNamespace
	if envNS := os.Getenv("PAAS_E2E_NS"); envNS != "" {
		ns = envNS
	} else {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: ns},
		})).To(Succeed())
	}

	// Create the empty secret that PaasConfig.DecryptKeysSecret points to.
	Expect(k8sClient.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: keysSecretName, Namespace: ns},
	})).To(Succeed())

	createPaasConfig(examplePaasConfig)
})

var _ = AfterSuite(func() {
	deleteResourceSync(&v1alpha2.PaasConfig{
		ObjectMeta: metav1.ObjectMeta{Name: paasConfigName},
	})
	deleteResourceSync(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: keysSecretName, Namespace: e2eNamespace},
	})
	if os.Getenv("PAAS_E2E_NS") == "" {
		deleteResourceSync(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: e2eNamespace},
		})
	}
	cancelCtx()
})
