/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

// Tests for: kubectl-paas reencrypt
//
// reencrypt:
//   Accepts one or more Paas YAML/JSON file paths as positional arguments.
//   --privateKeyFiles  the OLD private key (used for decryption).
//   --publicKeyFile    the NEW public key (used for re-encryption).
//   Decrypts every secret in-place and re-encrypts it with the new key,
//   then writes the modified YAML back to the same file.
//
// Three tests cover:
//   1. The file is actually modified after reencrypt.
//   2. The new private key can decrypt the re-encrypted secret.
//   3. The old private key can NO longer decrypt the re-encrypted secret.

import (
	"github.com/belastingdienst/opr-paas-cli/v2/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v5/api/v1alpha2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"
)

// decryptWithPrivKey decrypts a base64 ciphertext using a private key file.
func decryptWithPrivKey(privFile, paasName, encrypted string) ([]byte, error) {
	c, err := crypt.NewCryptFromFiles([]string{privFile}, "", paasName)
	Expect(err).NotTo(HaveOccurred())
	return c.Decrypt(encrypted)
}

// secretFromPaasYAML unmarshals a Paas YAML and returns the named secret value.
func secretFromPaasYAML(yamlContent, key string) string {
	var paas v1alpha2.Paas
	Expect(yaml.Unmarshal([]byte(yamlContent), &paas)).To(Succeed())
	val, ok := paas.Spec.Secrets[key]
	Expect(ok).To(BeTrue(), "secret %q not found in Paas", key)
	return val
}

var _ = Describe("reencrypt", func() {
	It("overwrites the encrypted value in the YAML file", func() {
		const paasName = "reencrypt-test"
		oldPriv, oldPub := freshKeyPair()
		_, newPub := freshKeyPair()

		encrypted := encryptWithPubKey(oldPub, paasName, "original-secret")
		paasFile := writeTempFile(paasWithSecret(paasName, encrypted), "paas.yaml")

		runCLI("reencrypt",
			"--privateKeyFiles", oldPriv,
			"--publicKeyFile", newPub,
			paasFile,
		)

		Expect(readFile(paasFile)).NotTo(ContainSubstring(encrypted),
			"original encrypted value should be replaced after key rotation")
	})

	It("the new private key can decrypt the re-encrypted secret", func() {
		const (
			paasName  = "reencrypt-newkey-test"
			plaintext = "my-database-password"
		)
		oldPriv, oldPub := freshKeyPair()
		newPriv, newPub := freshKeyPair()

		encrypted := encryptWithPubKey(oldPub, paasName, plaintext)
		paasFile := writeTempFile(paasWithSecret(paasName, encrypted), "paas.yaml")

		runCLI("reencrypt",
			"--privateKeyFiles", oldPriv,
			"--publicKeyFile", newPub,
			paasFile,
		)

		newEncrypted := secretFromPaasYAML(readFile(paasFile), "mysecret")
		decrypted, err := decryptWithPrivKey(newPriv, paasName, newEncrypted)
		Expect(err).NotTo(HaveOccurred(), "new private key must successfully decrypt")
		Expect(string(decrypted)).To(Equal(plaintext))
	})

	It("the old private key cannot decrypt after key rotation", func() {
		const paasName = "reencrypt-oldkey-test"
		oldPriv, oldPub := freshKeyPair()
		_, newPub := freshKeyPair()

		encrypted := encryptWithPubKey(oldPub, paasName, "secret-value")
		paasFile := writeTempFile(paasWithSecret(paasName, encrypted), "paas.yaml")

		runCLI("reencrypt",
			"--privateKeyFiles", oldPriv,
			"--publicKeyFile", newPub,
			paasFile,
		)

		newEncrypted := secretFromPaasYAML(readFile(paasFile), "mysecret")
		_, err := decryptWithPrivKey(oldPriv, paasName, newEncrypted)
		Expect(err).To(HaveOccurred(),
			"the old private key must not decrypt a secret re-encrypted with a new key")
	})
})
