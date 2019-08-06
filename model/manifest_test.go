package model

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManifestFileIsInvalid(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("123123 123123"), nil)

	assert.EqualError(t, err, "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `123123 ...` into map[string]interface {}")
}

func TestManifestConfigurationSectionNotFound(t *testing.T) {
	t.Parallel()

	_, err := GetManifest(strings.NewReader("roles: []"), nil)

	assert.EqualError(t, err, "'variables' section not found in manifest")
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

	m, err := GetManifest(strings.NewReader(exampleManifest), nil)
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

	_, err := GetManifest(strings.NewReader(duplicateNameManifest), nil)
	assert.EqualError(t, err, "Duplicate variable name found in manifest")
}

var templateManifest = `
instance_groups: []
variables:
- name: SSL_CERT
  options:
    secret: true
    ca: INTERNAL_CA_CERT
    role_name: "foo.{{.KUBERNETES_NAMESPACE}}"
    alternative_names:
    - "*.{{.DOMAIN}}"
    - "foo.{{.KUBERNETES_NAMESPACE}}"
    - "svc.{{.KUBERNETES_CLUSTER_DOMAIN}}"
    # The following entries only exist to prove that the template expander will leave
    # existing boolean/nil values as-is, and can replace string values with other types.
    test:
      array: [false, null, "{{.IT_IS_TRUE}}", "{{.NOTHING}}"]
      none: ~
      nothing: "{{.NOTHING}}"
      right: "{{.IT_IS_TRUE}}"
      wrong: false
  type: certificate
`

func TestExpandTemplates(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"DOMAIN":                    "domain",
		"KUBERNETES_CLUSTER_DOMAIN": "cluster.domain",
		"KUBERNETES_NAMESPACE":      "namespace",
		"IT_IS_TRUE":                "true",
		"NOTHING":                   "~",
	}
	m, err := GetManifest(strings.NewReader(templateManifest), env)
	assert.NoError(t, err)
	assert.Equal(t, "foo.namespace", m.Variables[0].CVOptions.RoleName)

	params, err := m.Variables[0].OptionsAsCertificateParams()
	assert.NoError(t, err)

	names := params.AlternativeNames
	assert.Len(t, names, 3)
	assert.Equal(t, "*.domain", names[0])
	assert.Equal(t, "foo.namespace", names[1])
	assert.Equal(t, "svc.cluster.domain", names[2])

	test := m.Variables[0].Options["test"].(map[interface{}]interface{})
	array := test["array"].([]interface{})
	assert.False(t, array[0].(bool))
	assert.Nil(t, array[1])
	assert.True(t, array[2].(bool))
	assert.Nil(t, array[3])

	value, ok := test["none"]
	assert.True(t, ok)
	assert.Nil(t, value)

	value, ok = test["nothing"]
	assert.True(t, ok)
	assert.Nil(t, value)

	value, ok = test["right"]
	assert.True(t, ok)
	assert.True(t, value.(bool))

	value, ok = test["wrong"]
	assert.True(t, ok)
	assert.False(t, value.(bool))
}
