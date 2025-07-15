/*
Copyright 2024, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

import (
	"testing"

	"github.com/belastingdienst/opr-paas-crypttool/pkg/crypt"
	"github.com/belastingdienst/opr-paas/v3/api/v1alpha2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Mocks ---

type MockCrypt struct {
	mock.Mock
}

func (m *MockCrypt) Decrypt(secret string) ([]byte, error) {
	args := m.Called(secret)
	return []byte(args.String(0)), args.Error(1)
}

func (m *MockCrypt) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

type MockCryptFactory struct {
	mock.Mock
	crypt crypt.Cryptor
}

func (f *MockCryptFactory) NewCryptFromFiles(privateKeyFiles []string, publicKeyFile string,
	paasName string) (crypt.Cryptor, error) {
	return f.crypt, nil
}

// --- Test ---

func TestReencryptPaasData_ReencryptsSecrets(t *testing.T) {
	// Arrange
	originalSecret := "old-encrypted"
	decryptedSecret := "decrypted"
	reencryptedSecret := "new-encrypted"

	paas := &v1alpha2.Paas{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-paas",
		},
		Spec: v1alpha2.PaasSpec{
			Secrets: map[string]string{
				"mysecret": originalSecret,
			},
			Capabilities: map[string]v1alpha2.PaasCapability{},
		},
	}
	paasAsString := "some yaml with old-encrypted"

	mockCrypt := new(MockCrypt)
	// srcCrypt.Decrypt returns decryptedSecret
	mockCrypt.On("Decrypt", originalSecret).Return(decryptedSecret, nil)
	// dstCrypt.Encrypt returns reencryptedSecret
	mockCrypt.On("Encrypt", []byte(decryptedSecret)).Return(reencryptedSecret, nil)

	mockFactory := &MockCryptFactory{crypt: mockCrypt}

	service := NewReencryptServiceWithDeps(nil, mockFactory)

	// Act
	result, err := service.ReencryptPaasData(paas, paasAsString, "priv.key", "pub.key")

	// Assert
	assert.NoError(t, err)
	assert.Equal(t, 0, result.ErrorCount)
	assert.Equal(t, reencryptedSecret, paas.Spec.Secrets["mysecret"])
	assert.Contains(t, result.UpdatedPaasString, reencryptedSecret)
	mockCrypt.AssertExpectations(t)
}
