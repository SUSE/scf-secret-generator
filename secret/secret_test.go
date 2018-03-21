package secret

import (
	"errors"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type MockBase struct {
	mock.Mock
}

type MockLog struct {
	MockBase
}

func (m *MockLog) Fatal(message ...interface{}) {
	m.Called(message)
}

type MockSecretInterface struct {
	MockBase
}

type MockSecretInterfaceMissing struct {
	MockSecretInterface
}

type MockSecretInterfaceUnknown struct {
	MockSecretInterface
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

	if name == LEGACY_SECRETS_NAME {
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
	return nil, errors.New("not found")
}

func (m *MockConfigMapInterface) Update(configMap *v1.ConfigMap) (*v1.ConfigMap, error) {
	m.Called(configMap)
	return nil, nil
}

func TestGetSecretConfig(t *testing.T) {
	var c MockConfigMapInterface
	c.On("Get", SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
	configMap := GetSecretConfig(&c)

	if assert.NotNil(t, configMap) {
		assert.Equal(t, SECRETS_CONFIGMAP_NAME, configMap.Name)
		assert.Equal(t, LEGACY_SECRETS_NAME, configMap.Data[CURRENT_SECRETS_NAME])
		assert.Equal(t, "0", configMap.Data[CURRENT_SECRETS_GENERATION])
	}
}

func TestGetSecrets(t *testing.T) {
	origLogFatal := logFatal
	origGetEnv := getEnv

	t.Run("ConfigMap and Secrets don't exist yet", func(t *testing.T) {
		var c MockConfigMapInterface
		c.On("Get", SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
		configMap := GetSecretConfig(&c)

		var s MockSecretInterface
		s.On("Get", LEGACY_SECRETS_NAME, metav1.GetOptions{})
		secrets := GetSecrets(&s, configMap)

		if assert.NotNil(t, secrets) {
			assert.Empty(t, secrets.Name)
		}
		// Current secrets name being empty signals that the configmap must be created, not updated
		assert.Empty(t, configMap.Data[CURRENT_SECRETS_NAME])
	})

	t.Run("ConfigMap names a secret that doesn't exist", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var c MockConfigMapInterface
		c.On("Get", SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
		configMap := GetSecretConfig(&c)
		configMap.Data[CURRENT_SECRETS_NAME] = "missing"

		var s MockSecretInterface
		s.On("Get", "missing", metav1.GetOptions{})

		var mockLog MockLog
		logFatal = mockLog.Fatal
		mockLog.On("Fatal", []interface{}{"Cannot get previous version of secrets using name 'missing'."})

		secrets := GetSecrets(&s, configMap)

		assert.Nil(t, secrets)
	})

	t.Run("ConfigMap names current secret that does exist", func(t *testing.T) {
		var c MockConfigMapInterface
		c.On("Get", SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
		configMap := GetSecretConfig(&c)
		configMap.Data[CURRENT_SECRETS_NAME] = "current-secret"

		var s MockSecretInterface
		s.On("Get", "current-secret", metav1.GetOptions{})
		secrets := GetSecrets(&s, configMap)

		if assert.NotNil(t, secrets) {
			// Name should be empty, only Data should be copied
			assert.Empty(t, secrets.Name)
			assert.Equal(t, []byte("data"), secrets.Data["dummy"])
		}
	})
}

func TestGenerateSecrets(t *testing.T) {
	origLogFatal := logFatal
	origGetEnv := getEnv
	defer func() {
		logFatal = origLogFatal
		getEnv = origGetEnv
	}()

	t.Run("Missing KUBE_SECRETS_GENERATION_COUNTER should logFatal", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// KUBE_SECRETS_GENERATION_COUNTER
			return ""
		}

		var c MockConfigMapInterface
		c.On("Get", SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
		configMap := GetSecretConfig(&c)

		var s MockSecretInterface
		s.On("Get", LEGACY_SECRETS_NAME, metav1.GetOptions{})
		secrets := GetSecrets(&s, configMap)

		mockLog.On("Fatal", []interface{}{"KUBE_SECRETS_GENERATION_COUNTER is missing or empty."})
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{},
				},
			},
		}
		GenerateSecrets(manifest, secrets, configMap)

		mockLog.AssertCalled(t, "Fatal", []interface{}{"KUBE_SECRETS_GENERATION_COUNTER is missing or empty."})
	})

	getEnv = func(ev string) string {
		// KUBE_SECRETS_GENERATION_COUNTER
		return "1"
	}

	t.Run("Non-generated secrets are removed", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		assert.Equal(t, []byte("obsolete"), secrets.Data["non-generated"])
		GenerateSecrets(manifest, secrets, configMap)
		assert.Empty(t, secrets.Data["non-generated"])
	})

	t.Run("New passwords is generated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		assert.Empty(t, secrets.Data["dirty"])
		GenerateSecrets(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["dirty"])
	})

	t.Run("Existing passwords isn't updated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		secrets.Data["clean"] = []byte("clean")
		GenerateSecrets(manifest, secrets, configMap)
		assert.Equal(t, []byte("clean"), secrets.Data["clean"])
	})

	t.Run("New SSH key is generated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		assert.Empty(t, secrets.Data["ssh-key"])
		assert.Empty(t, secrets.Data["ssh-key-fingerprint"])
		GenerateSecrets(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ssh-key"])
		assert.NotEmpty(t, secrets.Data["ssh-key-fingerprint"])
	})

	t.Run("Existing SSH key isn't updated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		secrets.Data["ssh-key"] = []byte("key")
		secrets.Data["ssh-key-fingerprint"] = []byte("fingerprint")

		GenerateSecrets(manifest, secrets, configMap)

		assert.Equal(t, []byte("key"), secrets.Data["ssh-key"])
		assert.Equal(t, []byte("fingerprint"), secrets.Data["ssh-key-fingerprint"])
	})

	t.Run("New SSL CA is generated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		assert.Empty(t, secrets.Data["ca-cert"])
		assert.Empty(t, secrets.Data["ca-key"])
		GenerateSecrets(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ca-cert"])
		assert.NotEmpty(t, secrets.Data["ca-key"])
	})

	t.Run("Existing SSL CA isn't updated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		secrets.Data["ca-cert"] = []byte("cert")
		secrets.Data["ca-key"] = []byte("key")
		GenerateSecrets(manifest, secrets, configMap)
		assert.Equal(t, []byte("cert"), secrets.Data["ca-cert"])
		assert.Equal(t, []byte("key"), secrets.Data["ca-key"])
	})

	t.Run("New SSL cert is generated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		assert.Empty(t, secrets.Data["ssl-cert"])
		assert.Empty(t, secrets.Data["ssl-key"])
		GenerateSecrets(manifest, secrets, configMap)
		assert.NotEmpty(t, secrets.Data["ssl-cert"])
		assert.NotEmpty(t, secrets.Data["ssl-key"])
	})

	t.Run("Existing SSL cert isn't updated", func(t *testing.T) {
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
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_GENERATION: "1"}}

		secrets.Data["ssl-cert"] = []byte("cert")
		secrets.Data["ssl-key"] = []byte("key")
		GenerateSecrets(manifest, secrets, configMap)
		assert.Equal(t, []byte("cert"), secrets.Data["ssl-cert"])
		assert.Equal(t, []byte("key"), secrets.Data["ssl-key"])
	})

}

func TestMigrateRenamedVariable(t *testing.T) {
	t.Run("NoPreviousNames", func(t *testing.T) {
		t.Parallel()

		// If `name` has no previous names, then it should remain empty
		secrets := &v1.Secret{Data: map[string][]byte{}}

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME"}
		migrateRenamedVariable(secrets, configVar)
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithoutValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, but without value, then it should remain empty
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, then it should copy the previous value
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("NewValueAlreadyExists", func(t *testing.T) {
		t.Parallel()

		// If `name` has a value, then it should not be changed
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["new-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNames", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first previous value
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNamesMissingSomeValues", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first non-empty previous value
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})
}

func TestUpdateSecrets(t *testing.T) {
	t.Parallel()

	origLogFatal := logFatal
	origGetEnv := getEnv
	defer func() {
		logFatal = origLogFatal
		getEnv = origGetEnv
	}()

	t.Run("Missing KUBE_SECRETS_GENERATION_NAME should logFatal", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// KUBE_SECRETS_GENERATION_NAME
			return ""
		}

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{}}

		mockLog.On("Fatal", []interface{}{"KUBE_SECRETS_GENERATION_NAME is missing or empty."})
		UpdateSecrets(&s, secrets, &c, configMap)

		s.AssertNotCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)

		mockLog.AssertCalled(t, "Fatal", []interface{}{"KUBE_SECRETS_GENERATION_NAME is missing or empty."})
	})

	t.Run("ConfigMap has no current secret", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// KUBE_SECRETS_GENERATION_NAME
			return "new-secret"
		}

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{}}
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		UpdateSecrets(&s, secrets, &c, configMap)

		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertNotCalled(t, "Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		c.AssertCalled(t, "Create", configMap)
		c.AssertNotCalled(t, "Update", configMap)

		mockLog.AssertNotCalled(t, "Fatal")
	})

	t.Run("ConfigMap has current secret but not previous secret", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// KUBE_SECRETS_GENERATION_NAME
			return "new-secret"
		}

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{CURRENT_SECRETS_NAME: LEGACY_SECRETS_NAME}}
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		UpdateSecrets(&s, secrets, &c, configMap)

		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertNotCalled(t, "Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)

		mockLog.AssertNotCalled(t, "Fatal")
	})

	t.Run("ConfigMap has current and previous secret", func(t *testing.T) {
		defer func() {
			logFatal = origLogFatal
			getEnv = origGetEnv
		}()

		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// KUBE_SECRETS_GENERATION_NAME
			return "new-secret"
		}

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		s.On("Create", secrets)
		s.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		var c MockConfigMapInterface
		configMap := &v1.ConfigMap{Data: map[string]string{
			CURRENT_SECRETS_NAME:  "current-secret",
			PREVIOUS_SECRETS_NAME: LEGACY_SECRETS_NAME,
		}}
		c.On("Create", configMap)
		c.On("Update", configMap)
		c.On("Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		UpdateSecrets(&s, secrets, &c, configMap)

		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		s.AssertCalled(t, "Delete", LEGACY_SECRETS_NAME, &metav1.DeleteOptions{})

		c.AssertNotCalled(t, "Create", configMap)
		c.AssertCalled(t, "Update", configMap)

		mockLog.AssertNotCalled(t, "Fatal")
	})
}
