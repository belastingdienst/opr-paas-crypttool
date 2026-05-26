/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

// Tests for: kubectl-paas check-paas
//
// check-paas:
//   Accepts one or more Paas YAML/JSON file paths as positional arguments.
//   --privateKeyFiles  path to the private key used to decrypt the secrets.
//   For each file it decrypts every secret in spec.secrets and
//   spec.capabilities[*].secrets. Exits non-zero if any decryption fails.
//
// Four tests cover:
//   1. Valid secrets pass the check (exit 0).
//   2. A wrong private key makes check-paas exit non-zero.
//   3. Missing positional file arguments produce an error.
//   4. A non-YAML file is rejected with a format error.

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("check-paas", func() {
	It("exits zero when all secrets decrypt correctly", func() {
		const paasName = "check-valid-paas"
		privFile, pubFile := freshKeyPair()

		encrypted := encryptWithPubKey(pubFile, paasName, "real-secret-value")
		paasFile := writeTempFile(paasWithSecret(paasName, encrypted), "paas.yaml")

		runCLI("check-paas", "--privateKeyFiles", privFile, paasFile)
	})

	It("exits non-zero when the private key does not match", func() {
		const paasName = "check-wrong-key-paas"
		_, pubFile := freshKeyPair()
		wrongPriv, _ := freshKeyPair()

		encrypted := encryptWithPubKey(pubFile, paasName, "another-secret")
		paasFile := writeTempFile(paasWithSecret(paasName, encrypted), "paas.yaml")

		out, err := runCLIExpectFailure("check-paas", "--privateKeyFiles", wrongPriv, paasFile)
		Expect(err).To(HaveOccurred(), "check-paas with wrong key must exit non-zero")
		Expect(strings.ToLower(out)).To(Or(ContainSubstring("error"), ContainSubstring("unable")))
	})

	It("fails without file arguments", func() {
		_, err := runCLIExpectFailure("check-paas", "--privateKeyFiles", "/dev/null")
		Expect(err).To(HaveOccurred(), "check-paas without file args must fail")
	})

	It("rejects non-YAML files", func() {
		privFile, _ := freshKeyPair()
		badFile := writeTempFile("this is not YAML }{{{", "bad.yaml")

		_, err := runCLIExpectFailure("check-paas", "--privateKeyFiles", privFile, badFile)
		Expect(err).To(HaveOccurred(), "check-paas on a non-YAML file must fail")
	})
})
