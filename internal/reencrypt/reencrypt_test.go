/*
Copyright 2025, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package reencrypt

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock for crypt.Crypt
type MockCrypt struct {
	mock.Mock
}

func (m *MockCrypt) Decrypt(encrypted string) ([]byte, error) {
	args := m.Called(encrypted)
	val, ok := args.Get(0).([]byte)
	if !ok && args.Get(0) != nil {
		panic("MockCrypt.Decrypt: expected []byte return value")
	}
	return val, args.Error(1)
}

func (m *MockCrypt) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	val, ok := args.Get(0).(string)
	if !ok && args.Get(0) != nil {
		panic("MockCrypt.Encrypt: expected string return value")
	}
	return val, args.Error(1)
}

const (
	testSecret      = "encrypted-secret"
	decryptedData   = "decrypted-data"
	reencryptedData = "reencrypted-secret"
)

func TestReencryptSecret(t *testing.T) {
	t.Run("successfully reencrypts secret", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return([]byte(decryptedData), nil)
		dstCrypt.On("Encrypt", []byte(decryptedData)).Return(reencryptedData, nil)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, reencryptedData, result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})

	t.Run("returns error when source decryption fails", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)
		decryptError := errors.New("decryption failed")

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return([]byte(nil), decryptError)
		// dstCrypt should not be called

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, decryptError, err)
		assert.Empty(t, result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertNotCalled(t, "Encrypt")
	})

	t.Run("returns error when destination encryption fails", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)
		encryptError := errors.New("encryption failed")

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return([]byte(decryptedData), nil)
		dstCrypt.On("Encrypt", []byte(decryptedData)).Return("", encryptError)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, encryptError, err)
		assert.Empty(t, result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})

	t.Run("handles empty secret", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)
		emptySecret := ""

		// Setup expectations
		srcCrypt.On("Decrypt", emptySecret).Return([]byte(""), nil)
		dstCrypt.On("Encrypt", []byte("")).Return("encrypted-empty", nil)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, emptySecret)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-empty", result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})

	t.Run("handles empty decrypted data", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return([]byte(""), nil)
		dstCrypt.On("Encrypt", []byte("")).Return("encrypted-empty", nil)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-empty", result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})

	t.Run("handles large data", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)
		largeData := make([]byte, largeDataSize)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return(largeData, nil)
		dstCrypt.On("Encrypt", largeData).Return("encrypted-large-data", nil)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-large-data", result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})

	t.Run("handles nil decrypted data", func(t *testing.T) {
		srcCrypt := new(MockCrypt)
		dstCrypt := new(MockCrypt)

		// Setup expectations
		srcCrypt.On("Decrypt", testSecret).Return([]byte(nil), nil)
		dstCrypt.On("Encrypt", []byte(nil)).Return("encrypted-nil", nil)

		// Execute
		result, err := reencryptSecret(srcCrypt, dstCrypt, testSecret)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, "encrypted-nil", result)
		srcCrypt.AssertExpectations(t)
		dstCrypt.AssertExpectations(t)
	})
}

// Benchmark tests
const (
	benchmarkDataSize = 1024  // 1KB
	largeDataSize     = 10240 // 10KB
)

func BenchmarkReencryptSecret(b *testing.B) {
	srcCrypt := new(MockCrypt)
	dstCrypt := new(MockCrypt)
	testData := make([]byte, benchmarkDataSize)

	// Setup mock expectations for benchmark
	srcCrypt.On("Decrypt", mock.AnythingOfType("string")).Return(testData, nil)
	dstCrypt.On("Encrypt", mock.AnythingOfType("[]uint8")).Return("encrypted", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reencryptSecret(srcCrypt, dstCrypt, "test-secret")
	}
}

// Table-driven test for multiple scenarios
func TestReencryptSecretTableDriven(t *testing.T) {
	tests := []struct {
		name           string
		secret         string
		decryptResult  []byte
		decryptError   error
		encryptResult  string
		encryptError   error
		expectedResult string
		expectedError  bool
	}{
		{
			name:           "successful reencryption",
			secret:         "secret1",
			decryptResult:  []byte("data1"),
			decryptError:   nil,
			encryptResult:  "encrypted1",
			encryptError:   nil,
			expectedResult: "encrypted1",
			expectedError:  false,
		},
		{
			name:           "decrypt fails",
			secret:         "secret2",
			decryptResult:  nil,
			decryptError:   errors.New("decrypt error"),
			encryptResult:  "",
			encryptError:   nil,
			expectedResult: "",
			expectedError:  true,
		},
		{
			name:           "encrypt fails",
			secret:         "secret3",
			decryptResult:  []byte("data3"),
			decryptError:   nil,
			encryptResult:  "",
			encryptError:   errors.New("encrypt error"),
			expectedResult: "",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcCrypt := new(MockCrypt)
			dstCrypt := new(MockCrypt)

			srcCrypt.On("Decrypt", tt.secret).Return(tt.decryptResult, tt.decryptError)
			if tt.decryptError == nil {
				dstCrypt.On("Encrypt", tt.decryptResult).Return(tt.encryptResult, tt.encryptError)
			}

			result, err := reencryptSecret(srcCrypt, dstCrypt, tt.secret)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedResult, result)

			srcCrypt.AssertExpectations(t)
			if tt.decryptError == nil {
				dstCrypt.AssertExpectations(t)
			}
		})
	}
}
