package crypt

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCrypt(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Crypt Suite")
}
