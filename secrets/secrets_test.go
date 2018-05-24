package secrets

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type MockBase struct {
	mock.Mock
}

type MockSecretInterface struct {
	MockBase
}

func (m *MockSecretInterface) Create(secret *v1.Secret) (*v1.Secret, error) {
	m.Called(secret)
	return nil, nil
}

func (m *MockSecretInterface) Delete(name string, options *metav1.DeleteOptions) error {
	m.Called(name, options)
	return nil
}

func (m *MockSecretInterface) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	if name == legacySecretName {
		return nil, errors.New("missing")
	} else if name == "missing" {
		return nil, errors.New("missing")
	} else {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Data: map[string][]byte{"dummy": []byte("data")},
		}

		secret.Data[name] = []byte(name)
		return &secret, nil
	}
}

func (m *MockSecretInterface) Update(secret *v1.Secret) (*v1.Secret, error) {
	m.Called(secret)
	return nil, nil
}

type MockConfigMapInterface struct {
	MockBase
}

func (m *MockConfigMapInterface) Create(configMap *v1.ConfigMap) (*v1.ConfigMap, error) {
	m.Called(configMap)
	return nil, nil
}

func (m *MockConfigMapInterface) Delete(name string, options *metav1.DeleteOptions) error {
	m.Called(name, options)
	return nil
}

func (m *MockConfigMapInterface) Get(name string, options metav1.GetOptions) (*v1.ConfigMap, error) {
	m.Called(name, options)
	if name == defaultSecretsConfigMapName {
		return nil, errors.New("not found")
	}
	return mockConfig(name), nil
}

func (m *MockConfigMapInterface) Update(configMap *v1.ConfigMap) (*v1.ConfigMap, error) {
	m.Called(configMap)
	return nil, nil
}

func mockConfig(name string) *v1.ConfigMap {
	configMap := defaultConfig(name)
	if name != defaultSecretsConfigMapName {
		configMap.Data[currentSecretNameKey] = "my-secret-name"
		configMap.Data[currentSecretGenerationKey] = "5"
		switch name {
		case "legacy":
			// no config version
		case "invalid":
			configMap.Data[configVersionKey] = "999"
		default:
			configMap.Data[configVersionKey] = currentConfigVersion
		}
	}
	return configMap
}

func setSecret(secrets *v1.Secret, configVar *model.ConfigurationVariable, value string) {
	name := util.ConvertNameToKey(configVar.Name)
	secrets.Data[name] = []byte(value)
	secrets.Data[name+generatorSuffix], _ = json.Marshal(configVar.Generator)
}

func testingSecretGenerator() SecretGenerator {
	return SecretGenerator{
		Domain:               "domain",
		Namespace:            "namespace",
		ServiceDomainSuffix:  "suffix",
		SecretsName:          "new-secret",
		SecretsGeneration:    "1",
		SecretsConfigMapName: defaultSecretsConfigMapName,
		CertExpiration:       365,
	}
}

func TestGetSecretConfig(t *testing.T) {
	t.Parallel()

	t.Run("ConfigMap doesn't exist yet", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})

		configMap, err := sg.getSecretConfig(&c)

		assert.NoError(t, err)
		c.AssertCalled(t, "Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		c.AssertCalled(t, "Create", configMap)
		c.AssertNotCalled(t, "Update", configMap)

		require.NotNil(t, configMap)
		assert.Equal(t, sg.SecretsConfigMapName, configMap.Name)
		assert.Equal(t, legacySecretName, configMap.Data[currentSecretNameKey])
		assert.Equal(t, "0", configMap.Data[currentSecretGenerationKey])
		assert.Equal(t, currentConfigVersion, configMap.Data[configVersionKey])
	})

	t.Run("ConfigMap already exists", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()
		sg.SecretsConfigMapName = "non-default-name"

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})

		configMap, err := sg.getSecretConfig(&c)

		assert.NoError(t, err)
		c.AssertCalled(t, "Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)

		require.NotNil(t, configMap)
		assert.Equal(t, sg.SecretsConfigMapName, configMap.Name)
		assert.Equal(t, "my-secret-name", configMap.Data[currentSecretNameKey])
		assert.Equal(t, "5", configMap.Data[currentSecretGenerationKey])
		assert.Equal(t, currentConfigVersion, configMap.Data[configVersionKey])
	})

	t.Run("ConfigMap exists but has no config-version", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()
		sg.SecretsConfigMapName = "legacy"

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})

		configMap, err := sg.getSecretConfig(&c)

		assert.NoError(t, err)
		c.AssertCalled(t, "Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)

		require.NotNil(t, configMap)
		assert.Equal(t, sg.SecretsConfigMapName, configMap.Name)
		assert.Equal(t, "my-secret-name", configMap.Data[currentSecretNameKey])
		assert.Equal(t, "5", configMap.Data[currentSecretGenerationKey])
		assert.Equal(t, currentConfigVersion, configMap.Data[configVersionKey])
	})

	t.Run("ConfigMap exists but has invalid version", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()
		sg.SecretsConfigMapName = "invalid"

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})

		configMap, err := sg.getSecretConfig(&c)

		assert.Error(t, err)
		assert.Nil(t, configMap)

		c.AssertCalled(t, "Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		c.AssertNotCalled(t, "Create", configMap)
		c.AssertNotCalled(t, "Update", configMap)
	})
}

func TestGetSecret(t *testing.T) {
	t.Parallel()

	t.Run("ConfigMap and Secret don't exist yet", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		configMap, err := sg.getSecretConfig(&c)
		assert.NoError(t, err)

		var s MockSecretInterface
		s.On("Get", legacySecretName, metav1.GetOptions{})

		secrets, err := sg.getSecret(&s, configMap)
		assert.NoError(t, err)

		require.NotNil(t, secrets)
		assert.Equal(t, "new-secret", secrets.Name)
	})

	t.Run("ConfigMap names a secret that doesn't exist", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		configMap, err := sg.getSecretConfig(&c)
		assert.NoError(t, err)
		configMap.Data[currentSecretNameKey] = "missing"

		var s MockSecretInterface
		s.On("Get", "missing", metav1.GetOptions{})

		_, err = sg.getSecret(&s, configMap)
		assert.Error(t, err, "Secret is not supposed to exist")
	})

	t.Run("ConfigMap names current secret that does exist", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Get", sg.SecretsConfigMapName, metav1.GetOptions{})
		configMap, err := sg.getSecretConfig(&c)
		assert.NoError(t, err)
		configMap.Data[currentSecretNameKey] = "current-secret"

		var s MockSecretInterface
		s.On("Get", "current-secret", metav1.GetOptions{})
		secrets, err := sg.getSecret(&s, configMap)
		assert.NoError(t, err)

		require.NotNil(t, secrets)
		assert.Equal(t, "new-secret", secrets.Name)
		assert.Equal(t, []byte("data"), secrets.Data["dummy"])
	})
}

func TestExpandTemplates(t *testing.T) {
	t.Parallel()

	sg := testingSecretGenerator()

	manifest := model.Manifest{
		Configuration: &model.Configuration{
			Variables: []*model.ConfigurationVariable{
				{
					Name:   "ssl-cert",
					Secret: true,
					Generator: &model.ConfigurationVariableGenerator{
						ID:        "sslcert",
						Type:      model.GeneratorTypeCertificate,
						ValueType: model.ValueTypeCertificate,
						SubjectNames: []string{
							"*.{{.DOMAIN}}",
							"foo.{{.KUBERNETES_NAMESPACE}}",
							"svc.{{.KUBE_SERVICE_DOMAIN_SUFFIX}}"},
					},
				},
			},
		},
	}

	err := sg.expandTemplates(manifest)
	assert.NoError(t, err)
	names := manifest.Configuration.Variables[0].Generator.SubjectNames
	assert.Len(t, names, 3)
	assert.Equal(t, "*.domain", names[0])
	assert.Equal(t, "foo.namespace", names[1])
	assert.Equal(t, "svc.suffix", names[2])
}

func TestGenerateSecret(t *testing.T) {
	t.Parallel()

	// The subtests cannot run in parallel because there are global variables in some generators
	t.Run("Non-generated secrets are removed", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "non-generated",
						Secret: true,
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{"non-generated": []byte("obsolete")}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		assert.Equal(t, []byte("obsolete"), secrets.Data["non-generated"])
		sg.generateSecret(manifest, secrets, configMap)
		assert.Empty(t, secrets.Data["non-generated"])
	})

	t.Run("New password is generated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "dirty",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypePassword,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		assert.Empty(t, secrets.Data["dirty"])
		assert.Empty(t, secrets.Data["dirty"+generatorSuffix])
		sg.generateSecret(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["dirty"])
		assert.NotEmpty(t, secrets.Data["dirty"+generatorSuffix])
	})

	t.Run("Existing password isn't updated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "clean",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypePassword,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[0], "clean")
		sg.generateSecret(manifest, secrets, configMap)
		assert.Equal(t, []byte("clean"), secrets.Data["clean"])
	})

	t.Run("Existing passwords is updated during rotation", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()
		sg.SecretsGeneration = "2"

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "clean",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypePassword,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[0], "clean")
		sg.generateSecret(manifest, secrets, configMap)
		assert.NotEqual(t, []byte("clean"), secrets.Data["clean"])
	})

	t.Run("Existing immutable password isn't updated during rotation", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()
		sg.SecretsGeneration = "2"

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:      "clean",
						Secret:    true,
						Immutable: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypePassword,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[0], "clean")
		sg.generateSecret(manifest, secrets, configMap)
		assert.Equal(t, []byte("clean"), secrets.Data["clean"])
	})

	t.Run("New SSH key is generated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ssh-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "ssh-key",
							Type:      model.GeneratorTypeSSH,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:   "ssh-key-fingerprint",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "ssh-key",
							Type:      model.GeneratorTypeSSH,
							ValueType: model.ValueTypeFingerprint,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		assert.Empty(t, secrets.Data["ssh-key"])
		assert.Empty(t, secrets.Data["ssh-key"+generatorSuffix])
		assert.Empty(t, secrets.Data["ssh-key-fingerprint"])
		assert.Empty(t, secrets.Data["ssh-key-fingerprint"+generatorSuffix])
		sg.generateSecret(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ssh-key"])
		assert.NotEmpty(t, secrets.Data["ssh-key"+generatorSuffix])
		assert.NotEmpty(t, secrets.Data["ssh-key-fingerprint"])
		assert.NotEmpty(t, secrets.Data["ssh-key-fingerprint"+generatorSuffix])
	})

	t.Run("Existing SSH key isn't updated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ssh-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "ssh-key",
							Type:      model.GeneratorTypeSSH,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:   "ssh-key-fingerprint",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "ssh-key",
							Type:      model.GeneratorTypeSSH,
							ValueType: model.ValueTypeFingerprint,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[0], "key")
		setSecret(secrets, manifest.Configuration.Variables[1], "fingerprint")

		sg.generateSecret(manifest, secrets, configMap)

		assert.Equal(t, []byte("key"), secrets.Data["ssh-key"])
		assert.Equal(t, []byte("fingerprint"), secrets.Data["ssh-key-fingerprint"])
	})

	t.Run("New SSL CA is generated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ca-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ca-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		assert.Empty(t, secrets.Data["ca-cert"])
		assert.Empty(t, secrets.Data["ca-cert"+generatorSuffix])
		assert.Empty(t, secrets.Data["ca-key"])
		assert.Empty(t, secrets.Data["ca-key"+generatorSuffix])
		sg.generateSecret(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ca-cert"])
		assert.NotEmpty(t, secrets.Data["ca-cert"+generatorSuffix])
		assert.NotEmpty(t, secrets.Data["ca-key"])
		assert.NotEmpty(t, secrets.Data["ca-key"+generatorSuffix])
	})

	t.Run("Existing SSL CA isn't updated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ca-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ca-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[0], "cert")
		setSecret(secrets, manifest.Configuration.Variables[1], "key")
		sg.generateSecret(manifest, secrets, configMap)
		assert.Equal(t, []byte("cert"), secrets.Data["ca-cert"])
		assert.Equal(t, []byte("key"), secrets.Data["ca-key"])
	})

	t.Run("New SSL cert is generated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ca-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ca-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:   "ssl-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ssl-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		assert.Empty(t, secrets.Data["ssl-cert"])
		assert.Empty(t, secrets.Data["ssl-cert"+generatorSuffix])
		assert.Empty(t, secrets.Data["ssl-key"])
		assert.Empty(t, secrets.Data["ssl-key"+generatorSuffix])
		sg.generateSecret(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ssl-cert"])
		assert.NotEmpty(t, secrets.Data["ssl-cert"+generatorSuffix])
		assert.NotEmpty(t, secrets.Data["ssl-key"])
		assert.NotEmpty(t, secrets.Data["ssl-key"+generatorSuffix])
	})

	t.Run("Existing SSL cert isn't updated", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ca-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ca-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:   "ssl-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ssl-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[2], "cert")
		setSecret(secrets, manifest.Configuration.Variables[3], "key")
		sg.generateSecret(manifest, secrets, configMap)
		assert.Equal(t, []byte("cert"), secrets.Data["ssl-cert"])
		assert.Equal(t, []byte("key"), secrets.Data["ssl-key"])
	})

	t.Run("Existing SSL cert is updated when SubjectNames change", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "ca-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ca-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "cacert",
							Type:      model.GeneratorTypeCACertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:   "ssl-cert",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:   "ssl-key",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "sslcert",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
					{
						Name:      "immutable-cert",
						Secret:    true,
						Immutable: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "immutable",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypeCertificate,
						},
					},
					{
						Name:      "immutable-key",
						Secret:    true,
						Immutable: true,
						Generator: &model.ConfigurationVariableGenerator{
							ID:        "immutable",
							Type:      model.GeneratorTypeCertificate,
							ValueType: model.ValueTypePrivateKey,
						},
					},
				},
			},
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		configMap := &v1.ConfigMap{Data: map[string]string{currentSecretGenerationKey: "1"}}

		setSecret(secrets, manifest.Configuration.Variables[2], "cert")
		setSecret(secrets, manifest.Configuration.Variables[3], "key")
		setSecret(secrets, manifest.Configuration.Variables[4], "cert2")
		setSecret(secrets, manifest.Configuration.Variables[5], "key2")

		manifest.Configuration.Variables[2].Generator.SubjectNames = []string{"*.domain"}
		manifest.Configuration.Variables[4].Generator.SubjectNames = []string{"*.domain"}

		assert.NotEmpty(t, secrets.Data["ssl-cert"])
		assert.NotEmpty(t, secrets.Data["ssl-cert"+generatorSuffix])
		assert.NotContains(t, string(secrets.Data["ssl-cert"+generatorSuffix]), "subject_names")

		assert.NotEmpty(t, secrets.Data["ssl-key"])
		assert.NotEmpty(t, secrets.Data["ssl-key"+generatorSuffix])

		sg.generateSecret(manifest, secrets, configMap)

		assert.NotEmpty(t, secrets.Data["ssl-cert"])
		assert.NotEmpty(t, secrets.Data["ssl-cert"+generatorSuffix])
		assert.Contains(t, string(secrets.Data["ssl-cert"+generatorSuffix]), "subject_names")

		assert.NotEmpty(t, secrets.Data["ssl-key"])
		assert.NotEmpty(t, secrets.Data["ssl-key"+generatorSuffix])

		assert.NotEqual(t, []byte("cert"), secrets.Data["ssl-cert"])
		assert.NotEqual(t, []byte("key"), secrets.Data["ssl-key"])

		assert.Equal(t, []byte("cert2"), secrets.Data["immutable-cert"])
		assert.Equal(t, []byte("key2"), secrets.Data["immutable-key"])
	})
}

func TestMigrateRenamedVariable(t *testing.T) {
	t.Parallel()

	t.Run("NoPreviousNames", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME"}
		migrateRenamedVariable(secrets, configVar)
		assert.Empty(t, string(secrets.Data["new-name"]),
			"If `name` has no previous names, then it should remain empty")
	})

	t.Run("PreviousNameWithoutValue", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Empty(t, string(secrets.Data["new-name"]),
			"If `name` has a previous name, but without value, then it should remain empty")
	})

	t.Run("PreviousNameWithValue", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]),
			"If `name` has a previous name, then it should copy the previous value")
	})

	t.Run("NewValueAlreadyExists", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["new-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]),
			"If `name` has a value, then it should not be changed")
	})

	t.Run("MultiplePreviousNames", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]),
			"If `name` has multiple previous names, then it should copy the first previous value")
	})

	t.Run("MultiplePreviousNamesMissingSomeValues", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]),
			"If `name` has multiple previous names, then it should copy the first non-empty previous value")
	})
}

func TestRollbackSecret(t *testing.T) {
	t.Parallel()

	sg := testingSecretGenerator()
	sg.SecretsName = legacySecretName

	var c MockConfigMapInterface
	configMap := &v1.ConfigMap{Data: map[string]string{
		configVersionKey:      "1",
		currentSecretNameKey:  "current-secret",
		previousSecretNameKey: sg.SecretsName,
	}}
	c.On("Update", configMap)

	err := sg.rollbackSecret(&c, configMap)

	assert.NoError(t, err)
	c.AssertCalled(t, "Update", configMap)

	assert.Equal(t, sg.SecretsName, configMap.Data[currentSecretNameKey])
	assert.Equal(t, "current-secret", configMap.Data[previousSecretNameKey])
}

func TestUpdateSecret(t *testing.T) {
	t.Run("ConfigMap has no current secret", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := mockConfig(sg.SecretsConfigMapName)
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		err := sg.updateSecret(&s, secrets, &c, configMap)

		assert.NoError(t, err)
		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertNotCalled(t, "Delete", legacySecretName, &metav1.DeleteOptions{})

		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)
	})

	t.Run("ConfigMap has current secret but not previous secret", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{
			configVersionKey:     "1",
			currentSecretNameKey: legacySecretName,
		}}
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		err := sg.updateSecret(&s, secrets, &c, configMap)

		assert.NoError(t, err)
		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertNotCalled(t, "Delete", legacySecretName, &metav1.DeleteOptions{})

		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)
	})

	t.Run("ConfigMap has current and previous secret", func(t *testing.T) {
		t.Parallel()

		sg := testingSecretGenerator()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{
			configVersionKey:      "1",
			currentSecretNameKey:  "current-secret",
			previousSecretNameKey: legacySecretName,
		}}
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", legacySecretName, &metav1.DeleteOptions{})

		err := sg.updateSecret(&s, secrets, &c, configMap)

		assert.NoError(t, err)
		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertCalled(t, "Delete", legacySecretName, &metav1.DeleteOptions{})

		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)
	})
}
