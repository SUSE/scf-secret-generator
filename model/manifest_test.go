package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestFileIsInvalid(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("123123 123123"))

	assert.EqualError(t, err, "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `123123 ...` into model.Manifest")
}

func TestManifestConfigurationSectionNotFound(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("roles: []"))

	assert.EqualError(t, err, "'Variables section' not found in manifest")
}

var exampleManifest = `
instance_groups: []
variables:
- { name: "a", type: "password" }
- name: "b"
  type: "certificate"
  options:
    secret: true
    ca: "default_ca"
    common_name: "example.com"
    alternative_names: ["other"]
- name: "c"
  type: "ssh"
  options: { description: "for example", required: true }
- name: APP_SSH_KEY
  options:
    secret: true
    description: PEM encoded RSA private key used to identify host.
    required: true  
`

var duplicateNameManifest = `
instance_groups: []
variables:
- { name: "a", type: "password" }
- { name: "a", type: "ssh" }
- name: APP_SSH_KEY
  options:
    secret: true
    description: PEM encoded RSA private key used to identify host.
    required: true  
`

func TestManifestConfigurationHasOptions(t *testing.T) {
	t.Parallel()

	m, err := GetManifest(strings.NewReader(exampleManifest))
	assert.NoError(t, err)

	for _, v := range m.Variables {
		assert.NotNil(t, v.Name)
	}
	v := m.Variables[0]
	assert.Equal(t, "a", v.Name)
	assert.Equal(t, VariableTypePassword, v.Type)
	assert.Equal(t, CVOptions{}, v.CVOptions)

	v = m.Variables[1]
	assert.Equal(t, "b", v.Name)
	assert.Equal(t, VariableTypeCertificate, v.Type)
	assert.Equal(t, "default_ca", v.Options["ca"])
	assert.Equal(t, true, v.CVOptions.Secret)
	assert.Nil(t, v.Options["secret"])

	v = m.Variables[2]
	assert.Equal(t, "c", v.Name)
	assert.Equal(t, VariableTypeSSH, v.Type)
	assert.Equal(t, false, v.CVOptions.Secret)

	v = m.Variables[3]
	assert.Equal(t, "APP_SSH_KEY", v.Name)
	assert.Equal(t, EmptyType, v.Type)
}

func TestManifestUniqueNames(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader(duplicateNameManifest))
	assert.EqualError(t, err, "Duplicate variable name found in manifest")
}
