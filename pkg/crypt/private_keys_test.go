package crypt

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("PrivateKeys", func() {
	Context("getting PublicKey from private key(s)", func() {
		When("when multiple private keys are present and one is the 'current' key", func() {
			It("it should return the public key belonging to the 'current' private key", func() {
				// generate private keys
				privateFile1, err := os.CreateTemp("", "private1")
				Expect(err).NotTo(HaveOccurred())
				defer os.Remove(privateFile1.Name()) // clean up

				privateFile2, err := os.CreateTemp("", "private2")
				Expect(err).NotTo(HaveOccurred())
				defer os.Remove(privateFile2.Name()) // clean up

				// write private keys to files
				pk1, err := GeneratePrivateKey()
				err = pk1.WritePrivateKey(privateFile1.Name())
				Expect(err).NotTo(HaveOccurred())

				pk2, err := GeneratePrivateKey()
				pk2.isCurrent = true
				err = pk2.WritePrivateKey(privateFile2.Name())
				Expect(err).NotTo(HaveOccurred())

				privateKeys := PrivateKeys{
					"pk1": pk1,
					"pk2": pk2,
				}

				// get public key from private keys
				key, err := privateKeys.PublicKey()

				Expect(err).NotTo(HaveOccurred())
				Expect(key).To(Equal(&pk2.privateKey.PublicKey))
			})
		})
		When("when multiple private keys are present and there is no 'current' key", func() {
			It("it should return an error", func() {
				// generate private keys
				privateFile1, err := os.CreateTemp("", "private1")
				Expect(err).NotTo(HaveOccurred())
				defer os.Remove(privateFile1.Name()) // clean up

				privateFile2, err := os.CreateTemp("", "private2")
				Expect(err).NotTo(HaveOccurred())
				defer os.Remove(privateFile2.Name()) // clean up

				// write private keys to files
				pk1, err := GeneratePrivateKey()
				err = pk1.WritePrivateKey(privateFile1.Name())
				Expect(err).NotTo(HaveOccurred())

				pk2, err := GeneratePrivateKey()
				err = pk2.WritePrivateKey(privateFile2.Name())
				Expect(err).NotTo(HaveOccurred())

				privateKeys := PrivateKeys{
					"pk1": pk1,
					"pk2": pk2,
				}

				// get public key from private keys
				key, err := privateKeys.PublicKey()

				Expect(err).To(HaveOccurred())
				Expect(key).To(BeNil())
			})
		})
		When("when one private key is present", func() {
			It("it should return the public key belonging to the private key", func() {
				// generate private key
				privateFile1, err := os.CreateTemp("", "private1")
				Expect(err).NotTo(HaveOccurred())
				defer os.Remove(privateFile1.Name()) // clean up

				// write private key to file
				pk1, err := GeneratePrivateKey()
				err = pk1.WritePrivateKey(privateFile1.Name())
				Expect(err).NotTo(HaveOccurred())

				// get public key from private keys
				privateKeys := PrivateKeys{
					"pk1": pk1,
				}

				key, err := privateKeys.PublicKey()
				Expect(err).NotTo(HaveOccurred())
				Expect(key).To(Equal(&pk1.privateKey.PublicKey))
			})
		})
		When("no private keys are present", func() {
			It("it should return an error", func() {
				// no private keys present
				privateKeys := PrivateKeys{}

				key, err := privateKeys.PublicKey()
				Expect(err).To(HaveOccurred())
				Expect(key).To(BeNil())
			})
		})
	})
})
