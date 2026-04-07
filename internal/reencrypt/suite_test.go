package reencrypt_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestReencrypt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Reencrypt Suite")
}
