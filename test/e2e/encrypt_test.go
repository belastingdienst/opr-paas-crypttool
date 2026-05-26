/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

// revive:disable:dot-imports

package e2e

// Tests for: kubectl-paas encrypt / kubectl-paas decrypt
//
// encrypt:
//   --publicKeyFile  (or --privateKeyFiles) selects file-based keys, skipping k8s.
//   --paas           (required) sets the RSA-OAEP encryption context.
//   --dataFile       reads plaintext from a file; omit to read from stdin.
//   --outputFormat   raw (default) prints the base64 ciphertext.
//
// decrypt:
//   --privateKeyFiles  path to private key file(s).
//   --paas             must match the context used during encryption.
//   Reads ciphertext from stdin, prints plaintext to stdout.
//
// All tests use file-based keys and raw output — no k8s queries beyond
// the mandatory PersistentPreRunE client setup.

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("encrypt", func() {
	var privFile, pubFile string

	BeforeEach(func() {
		privFile, pubFile = freshKeyPair()
	})

	It("produces non-empty base64 ciphertext in raw mode", func() {
		dataFile := writeTempFile("hello-world", "data.txt")

		out := strings.TrimSpace(runCLI("encrypt",
			"--publicKeyFile", pubFile,
			"--paas", "test-paas",
			"--dataFile", dataFile,
			"--outputFormat", "raw",
		))

		Expect(out).NotTo(BeEmpty())
		Expect(out).To(MatchRegexp(`^[A-Za-z0-9+/=]+$`), "raw output should be base64")
	})

	It("produces different ciphertext each time (RSA-OAEP is non-deterministic)", func() {
		dataFile := writeTempFile("same-plaintext", "data.txt")

		out1 := strings.TrimSpace(runCLI("encrypt",
			"--publicKeyFile", pubFile, "--paas", "test-paas",
			"--dataFile", dataFile, "--outputFormat", "raw",
		))
		out2 := strings.TrimSpace(runCLI("encrypt",
			"--publicKeyFile", pubFile, "--paas", "test-paas",
			"--dataFile", dataFile, "--outputFormat", "raw",
		))

		Expect(out1).NotTo(Equal(out2))
	})

	It("fails without --paas flag", func() {
		_, err := runCLIExpectFailure("encrypt",
			"--publicKeyFile", pubFile,
			"--outputFormat", "raw",
		)
		Expect(err).To(HaveOccurred(), "encrypt without --paas must fail")
	})

	It("reads plaintext from stdin when --dataFile is omitted", func() {
		out := strings.TrimSpace(runCLIWithStdin("stdin-secret\n",
			"encrypt",
			"--publicKeyFile", pubFile,
			"--paas", "test-paas",
			"--outputFormat", "raw",
		))

		Expect(out).NotTo(BeEmpty())
		Expect(out).To(MatchRegexp(`^[A-Za-z0-9+/=]+$`))
	})

	Describe("round trip", func() {
		It("decrypt(encrypt(x)) == x", func() {
			const plaintext = "super-secret-database-password"
			const paasName = "round-trip-paas"

			dataFile := writeTempFile(plaintext, "plain.txt")

			encrypted := strings.TrimSpace(runCLI("encrypt",
				"--publicKeyFile", pubFile,
				"--paas", paasName,
				"--dataFile", dataFile,
				"--outputFormat", "raw",
			))
			Expect(encrypted).NotTo(BeEmpty())

			decrypted := strings.TrimSpace(runCLIWithStdin(encrypted,
				"decrypt",
				"--privateKeyFiles", privFile,
				"--paas", paasName,
			))

			Expect(decrypted).To(Equal(plaintext))
		})
	})
})
