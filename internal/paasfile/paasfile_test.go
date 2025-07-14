/*
Copyright 2023, Tax Administration of The Netherlands.
Licensed under the EUPL 1.2.
See LICENSE.md for details.
*/

package paasfile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/belastingdienst/opr-paas-crypttool/internal/utils"
	"github.com/belastingdienst/opr-paas/v3/api/v1alpha2"
	"github.com/belastingdienst/opr-paas/v3/pkg/quota"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var equalErrMsg = `Error should be: %v, got: %v`

func TestReadPaasFile(t *testing.T) {
	expectedPaas := &v1alpha2.Paas{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Paas",
			APIVersion: "cpet.belastingdienst.nl/v1alpha2",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "tst-tst",
		},
		Spec: v1alpha2.PaasSpec{
			Quota:        quota.Quota{},
			Capabilities: v1alpha2.PaasCapabilities{},
			Groups:       v1alpha2.PaasGroups{},
			Namespaces:   v1alpha2.PaasNamespaces{},
		},
		Status: v1alpha2.PaasStatus{},
	}

	// invalid path
	paas, typeString, err := ReadPaasFile("invalid/path")
	expectedErrorMsg := "open invalid/path: no such file or directory"
	assert.EqualErrorf(
		t,
		err,
		expectedErrorMsg,
		equalErrMsg,
		expectedErrorMsg,
		err,
	) //nolint:testifylint // just no
	assert.Nil(t, paas)
	assert.Equal(t, FiletypeUnknown, typeString)

	// empty yaml file
	paas, typeString, err = ReadPaasFile("testdata/emptyPaas.yml")
	expectedErrorMsg = "empty paas file"
	require.Error(t, err)
	assert.Nil(t, paas)
	assert.Empty(t, typeString)
	assert.EqualErrorf(
		t,
		err,
		expectedErrorMsg,
		equalErrMsg,
		expectedErrorMsg,
		err,
	) //nolint:testifylint

	// empty json file
	paas, typeString, err = ReadPaasFile("testdata/emptyPaas.json")
	expectedErrorMsg = "empty paas file"
	require.Error(t, err)
	assert.Nil(t, paas)
	assert.Empty(t, typeString)
	assert.EqualErrorf(
		t,
		err,
		expectedErrorMsg,
		equalErrMsg,
		expectedErrorMsg,
		err,
	) //nolint:testifylint

	// minimal yaml file
	paas, typeString, err = ReadPaasFile("testdata/minimalPaas.yml")
	require.NoError(t, err)
	assert.Equal(t, expectedPaas, paas)
	assert.Equal(t, FiletypeYAML, typeString)
	assert.NotEqual(t, FiletypeJSON, typeString)

	// minimal json file
	paas, typeString, err = ReadPaasFile("testdata/minimalPaas.json")
	require.NoError(t, err)
	assert.Equal(t, expectedPaas, paas)
	assert.Equal(t, FiletypeJSON, typeString)
	assert.NotEqual(t, FiletypeYAML, typeString)

	// unsupported field in yaml file
	paas, typeString, err = ReadPaasFile("testdata/unsupportedFieldsPaas.yml")
	require.NoError(t, err)
	assert.Equal(t, expectedPaas, paas)
	assert.Equal(t, FiletypeYAML, typeString)
	assert.NotEqual(t, FiletypeJSON, typeString)

	// invalid file format
	paas, typeString, err = ReadPaasFile("testdata/invalidFormat.toml")
	assert.Nil(t, paas)
	assert.Empty(t, typeString)
	assert.EqualErrorf(
		t,
		err,
		"file 'testdata/invalidFormat.toml' is not in a supported file format",
		"Invalid file format should result in error",
	)
}

func TestHashData(t *testing.T) {
	testString := "My Wonderful Test String"
	out := utils.HashData([]byte(testString))

	assert.Equal(
		t,
		// revive:disable-next-line
		"703fe1668c39ec0fdf3c9916d526ba4461fe10fd36bac1e2a1b708eb8a593e418eb3f92dbbd2a6e3776516b0e03743a45cfd69de6a3280afaa90f43fa1918f74",
		out,
	)
}

func TestWriteFile(t *testing.T) {
	t.Run("successfully writes file", func(t *testing.T) {
		// Create temp directory
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// Test data
		buffer := []byte("test content")
		path := filepath.Join(tempDir, "test.txt")

		// Execute
		err = WriteFile(buffer, path)

		// Assert
		assert.NoError(t, err)

		// Verify file was created and has correct content
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, buffer, content)
	})

	t.Run("returns error when path is invalid", func(t *testing.T) {
		buffer := []byte("test content")
		invalidPath := "/invalid/nonexistent/path/file.txt"

		err := WriteFile(buffer, invalidPath)

		assert.Error(t, err)
	})

	t.Run("handles empty buffer", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		buffer := []byte{}
		path := filepath.Join(tempDir, "empty.txt")

		err = WriteFile(buffer, path)

		assert.NoError(t, err)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Empty(t, content)
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		path := filepath.Join(tempDir, "overwrite.txt")

		// Create initial file
		initialContent := []byte("initial content")
		err = WriteFile(initialContent, path)
		require.NoError(t, err)

		// Overwrite with new content
		newContent := []byte("new content")
		err = WriteFile(newContent, path)

		assert.NoError(t, err)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, newContent, content)
	})
}

func TestWriteFormattedFile(t *testing.T) {
	// Mock Paas object for testing
	mockPaas := &v1alpha2.Paas{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Paas",
			APIVersion: "cpet.belastingdienst.nl/v1alpha2",
		},
		Spec: v1alpha2.PaasSpec{
			Requestor: "paasfile_test",
		},
	}

	t.Run("writes JSON format successfully", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		path := filepath.Join(tempDir, "test.json")

		err = WriteFormattedFile(mockPaas, path, FiletypeJSON)

		assert.NoError(t, err)

		// Verify file content is valid JSON
		content, err := os.ReadFile(path)
		require.NoError(t, err)

		var result v1alpha2.Paas
		err = json.Unmarshal(content, &result)
		assert.NoError(t, err)
	})

	t.Run("writes YAML format successfully", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		path := filepath.Join(tempDir, "test.yaml")

		err = WriteFormattedFile(mockPaas, path, FiletypeYAML)

		assert.NoError(t, err)

		// Verify file content is valid YAML
		content, err := os.ReadFile(path)
		require.NoError(t, err)

		var result v1alpha2.Paas
		err = yaml.Unmarshal(content, &result)
		assert.NoError(t, err)
	})

	t.Run("returns error for invalid format", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		path := filepath.Join(tempDir, "test.txt")
		invalidFormat := FiletypeUnknown

		err = WriteFormattedFile(mockPaas, path, invalidFormat)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid output format")
	})

	t.Run("returns error when WriteFile fails", func(t *testing.T) {
		invalidPath := "/invalid/nonexistent/path/file.json"

		err := WriteFormattedFile(mockPaas, invalidPath, FiletypeJSON)

		assert.Error(t, err)
	})

	t.Run("handles nil Paas object", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		path := filepath.Join(tempDir, "test.json")

		err = WriteFormattedFile(nil, path, FiletypeJSON)

		assert.NoError(t, err)

		// Verify file contains "null"
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "null", string(content))
	})
}
