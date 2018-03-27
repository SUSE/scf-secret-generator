package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestFileIsInvalid(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("123123 123123"))

	if assert.Error(t, err) {
		assert.Equal(t, "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `123123 ...` into model.Manifest", err.Error())
	}
}

func TestManifestConfigurationSectionNotFound(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("roles: []"))
	if assert.Error(t, err) {
		assert.Equal(t, "'configuration section' not found in manifest", err.Error())
	}
}
