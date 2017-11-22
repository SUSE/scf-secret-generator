package model

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"gopkg.in/yaml.v2"
)

type MockLog struct {
	mock.Mock
}

func (m *MockLog) Fatal(message ...interface{}) {
	m.Called(message)
}

func TestManifestFileIsInvalid(t *testing.T) {
	origLogFatal := logFatal
	origFileReader := fileReader
	defer func() {
		logFatal = origLogFatal
		fileReader = origFileReader
	}()

	var mockLog MockLog

	yamlError := yaml.TypeError{Errors: []string{"line 1: cannot unmarshal !!str `123123 ...` into model.Manifest"}}

	mockLog.On("Fatal", []interface{}{&yamlError}).Return(nil)

	logFatal = mockLog.Fatal

	fileReader = func(name string) ([]byte, error) {
		return []byte("123123 123123"), nil
	}

	GetManifest("fake-name")

	mockLog.AssertCalled(t, "Fatal", []interface{}{&yamlError})
}

func TestManifestFileNotFound(t *testing.T) {
	origLogFatal := logFatal
	origFileReader := fileReader
	defer func() {
		logFatal = origLogFatal
		fileReader = origFileReader
	}()

	var mockLog MockLog

	mockLog.On("Fatal", []interface{}{errors.New("Not found")}).Return(nil)

	logFatal = mockLog.Fatal

	fileReader = func(name string) ([]byte, error) {
		return nil, errors.New("Not found")
	}

	GetManifest("fake-name")

	mockLog.AssertCalled(t, "Fatal", []interface{}{errors.New("Not found")})
}

func TestManifestConfigurationSectionNotFound(t *testing.T) {
	manifestText := `---
roles: []
`

	origLogFatal := logFatal
	origFileReader := fileReader
	defer func() {
		logFatal = origLogFatal
		fileReader = origFileReader
	}()

	var mockLog MockLog

	fileReader = func(name string) ([]byte, error) {
		return []byte(manifestText), nil
	}

	mockLog.On("Fatal", []interface{}{"'configuration section' not found in manifest"}).Return(nil)

	logFatal = mockLog.Fatal

	GetManifest("fake-name")

	mockLog.AssertCalled(t, "Fatal", []interface{}{"'configuration section' not found in manifest"})
}
