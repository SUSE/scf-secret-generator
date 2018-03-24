package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestFileIsInvalid(t *testing.T) {
	_, err := GetManifest("---\n123123 123123")

	if assert.Error(t, err) {
		assert.Equal(t, "yaml: unmarshal errors:\n  line 2: cannot unmarshal !!str `123123 ...` into model.Manifest", err.Error())
	}
}

func TestManifestFileNotFound(t *testing.T) {
	_, err := GetManifest("/this/file/does/not/exist")

	if assert.Error(t, err) {
		assert.Equal(t, "open /this/file/does/not/exist: no such file or directory", err.Error())
	}
}

func TestManifestConfigurationSectionNotFound(t *testing.T) {
	_, err := GetManifest("---\nroles: []")
	if assert.Error(t, err) {
		assert.Equal(t, "'configuration section' not found in manifest", err.Error())
	}
}
