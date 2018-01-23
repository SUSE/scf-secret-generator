package secret

import (
	"errors"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/ssh"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

func (m *MockSecretInterface) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	if name == SECRET_UPDATE_NAME+"-missing" {
		return nil, errors.New("missing")
	} else if name == "notfound" {
		resource := schema.GroupResource{}
		return nil, k8serrors.NewNotFound(resource, "")
	} else if name == "unknownerr" {
		return nil, errors.New("unknown")
	} else {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: SECRET_NAME,
			},
			Data: map[string][]byte{},
		}

		secret.Data[name] = []byte(name)
		return &secret, nil
	}
}

func (m *MockSecretInterface) Update(secret *v1.Secret) (*v1.Secret, error) {
	m.Called(secret)
	return nil, nil
}

func (m *MockSecretInterfaceMissing) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	if name == SECRET_NAME {
		resource := schema.GroupResource{}
		return nil, k8serrors.NewNotFound(resource, "")
	} else {
		secret := v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: SECRET_NAME,
			},
			Data: map[string][]byte{},
		}

		secret.Data[name] = []byte(name)
		return &secret, nil
	}
}

func (m *MockSecretInterfaceUnknown) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	return nil, errors.New("unknownerr")
}

type MockSecrets struct {
	MockBase
}

func (m *MockSecrets) PassGenerate(secretData, updateData map[string][]byte, secretName string) bool {
	results := m.Called(secretData, updateData, secretName)
	return results.Bool(0)
}

func (m *MockSecrets) SSHKeyGenerate(secretData, updateData map[string][]byte, key ssh.SSHKey) bool {
	results := m.Called(secretData, updateData, key)
	return results.Bool(0)
}

func (m *MockSecrets) RecordSSHKeyInfo(keys map[string]ssh.SSHKey, configVar *model.ConfigurationVariable) {
	m.Called(keys, configVar)
	keys[configVar.Name] = ssh.SSHKey{}
}

func (m *MockSecrets) RecordSSLCertInfo(configVar *model.ConfigurationVariable) {
	m.Called(configVar)
}

func (m *MockSecrets) GenerateSSLCerts(secrets, updates *v1.Secret) (dirty bool) {
	results := m.Called(secrets, updates)
	return results.Bool(0)
}

func TestUpdateSecretsWhenCreatingOrUpdating(t *testing.T) {
	t.Parallel()

	t.Run("Neither Create Nor Update called", func(t *testing.T) {
		var s MockSecretInterface
		s.On("Create", (*v1.Secret)(nil)).Return(nil, nil)
		s.On("Update", (*v1.Secret)(nil)).Return(nil, nil)

		UpdateSecrets(&s, nil, false, false)
		s.AssertNotCalled(t, "Create", nil)
		s.AssertNotCalled(t, "Update", nil)
	})

	t.Run("Create, but don't update", func(t *testing.T) {
		var s MockSecretInterface
		s.On("Create", (*v1.Secret)(nil)).Return(nil, nil)
		s.On("Update", (*v1.Secret)(nil)).Return(nil, nil)

		UpdateSecrets(&s, nil, true, false)
		s.AssertCalled(t, "Create", (*v1.Secret)(nil))
		s.AssertNotCalled(t, "Update", nil)
	})

	t.Run("Create and update called", func(t *testing.T) {
		var s MockSecretInterface
		s.On("Create", (*v1.Secret)(nil)).Return(nil, nil)
		s.On("Update", (*v1.Secret)(nil)).Return(nil, nil)

		UpdateSecrets(&s, nil, true, true)
		s.AssertCalled(t, "Create", (*v1.Secret)(nil))
		s.AssertNotCalled(t, "Update", (*v1.Secret)(nil))
	})

	t.Run("Update, but don't create", func(t *testing.T) {
		var s MockSecretInterface
		s.On("Create", (*v1.Secret)(nil)).Return(nil, nil)
		s.On("Update", (*v1.Secret)(nil)).Return(nil, nil)

		UpdateSecrets(&s, nil, false, true)
		s.AssertNotCalled(t, "Create", (*v1.Secret)(nil))
		s.AssertCalled(t, "Update", (*v1.Secret)(nil))
	})
}

func TestGetOrCreateWithValidSecrets(t *testing.T) {
	origLogFatal := logFatal
	origGetEnv := getEnv
	defer func() {
		logFatal = origLogFatal
		getEnv = origGetEnv
	}()

	t.Run("Missing secret-updates should logFatal", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return "missing"
		}
		mockLog.On("Fatal", []interface{}{errors.New("missing")})
		s.On("Get", SECRET_UPDATE_NAME+"-missing", metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})

		_, _, _ = GetOrCreateSecrets(&s)

		mockLog.AssertCalled(t, "Fatal", []interface{}{errors.New("missing")})
		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-missing", metav1.GetOptions{})
		s.AssertNotCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
	})

	t.Run("secret-updates with revision should append revision to secret requested", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return "1234"
		}
		s.On("Get", SECRET_UPDATE_NAME+"-1234", metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})
		_, _, _ = GetOrCreateSecrets(&s)
		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-1234", metav1.GetOptions{})
	})

	t.Run("Valid secret-updates should call get with SECRET_NAME and return that secret", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		s.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})
		create, secrets, _ := GetOrCreateSecrets(&s)
		s.AssertCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
		assert.Equal(t, []byte(SECRET_NAME), secrets.Data[SECRET_NAME])
		assert.False(t, create)
	})

	t.Run("Missing secret should return IsNotFound and create a secret", func(t *testing.T) {
		var sMissing MockSecretInterfaceMissing
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		sMissing.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		sMissing.On("Get", SECRET_NAME, metav1.GetOptions{})
		create, secrets, updates := GetOrCreateSecrets(&sMissing)
		assert.True(t, create)
		assert.NotNil(t, secrets)
		assert.NotNil(t, updates)
	})

	t.Run("Unrelated Get error for SECRET_NAME should logFatal", func(t *testing.T) {
		var sUnknown MockSecretInterfaceUnknown
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		mockLog.On("Fatal", []interface{}{errors.New("unknownerr")})
		sUnknown.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		sUnknown.On("Get", SECRET_NAME, metav1.GetOptions{})
		_, _, _ = GetOrCreateSecrets(&sUnknown)
		mockLog.AssertCalled(t, "Fatal", []interface{}{errors.New("unknownerr")})
	})
}

func TestGenerateSecretsWithNoSecrets(t *testing.T) {
	origPassGenerate := passGenerate
	origSshKeyGenerate := sshKeyGenerate
	origRecordSSHKeyInfo := recordSSHKeyInfo
	origRecordSSLCertInfo := recordSSLCertInfo
	origGenerateSSLCerts := generateSSLCerts

	defer func() {
		passGenerate = origPassGenerate
		sshKeyGenerate = origSshKeyGenerate
		recordSSHKeyInfo = origRecordSSHKeyInfo
		recordSSLCertInfo = origRecordSSLCertInfo
		generateSSLCerts = origGenerateSSLCerts
	}()

	t.Run("Manifest with no secrets doesn't change", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{Variables: []*model.ConfigurationVariable{}},
		}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", (*v1.Secret)(nil), (*v1.Secret)(nil)).Return(false)
		dirty := GenerateSecrets(manifest, nil, nil)
		assert.False(t, dirty)
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", (*v1.Secret)(nil), (*v1.Secret)(nil))
	})

	t.Run("Passwords are updated", func(t *testing.T) {
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

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		passGenerate = mockSecrets.PassGenerate
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("PassGenerate", map[string][]byte{}, map[string][]byte{}, "dirty").Return(true)
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.True(t, dirty)
		mockSecrets.AssertCalled(t, "PassGenerate", map[string][]byte{}, map[string][]byte{}, "dirty")
	})

	t.Run("Existing passwords aren't updated", func(t *testing.T) {
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

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		passGenerate = mockSecrets.PassGenerate
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("PassGenerate", map[string][]byte{}, map[string][]byte{}, "clean").Return(false)
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.False(t, dirty)
		mockSecrets.AssertCalled(t, "PassGenerate", map[string][]byte{}, map[string][]byte{}, "clean")
	})

	t.Run("Non-generated secrets aren't updated", func(t *testing.T) {
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

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)

		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.False(t, dirty)
	})

	t.Run("Non-generated updates are written to secrets", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "NON_GENERATED",
						Secret: true,
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		updates.Data["non-generated"] = []byte("password")

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", &secrets, &secrets).Return(false)

		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.True(t, dirty)
		assert.Equal(t, []byte("password"), secrets.Data["non-generated"])
	})

	t.Run("An updated SSH key is generated", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "dirty",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeSSH,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSHKeyInfo = mockSecrets.RecordSSHKeyInfo
		sshKeyGenerate = mockSecrets.SSHKeyGenerate
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
		mockSecrets.On("SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{}).Return(true)
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.True(t, dirty)
		mockSecrets.AssertCalled(t, "SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{})
		mockSecrets.AssertCalled(t, "RecordSSHKeyInfo", map[string]ssh.SSHKey{"dirty": ssh.SSHKey{}}, manifest.Configuration.Variables[0])
	})

	t.Run("An SSH key that doesn't need to be generated isn't updated", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "clean",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeSSH,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		recordSSHKeyInfo = mockSecrets.RecordSSHKeyInfo
		sshKeyGenerate = mockSecrets.SSHKeyGenerate
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
		mockSecrets.On("SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{}).Return(false)
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.False(t, dirty)
		mockSecrets.AssertCalled(t, "SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{})
		mockSecrets.AssertCalled(t, "RecordSSHKeyInfo", map[string]ssh.SSHKey{"clean": ssh.SSHKey{}}, manifest.Configuration.Variables[0])
	})

	t.Run("An SSL CA cert is updated", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "dirty",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeCACertificate,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(true)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.True(t, dirty)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)
	})

	t.Run("An SSL CA cert that isn't updated is unchanged", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "clean",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeCACertificate,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.False(t, dirty)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)
	})

	t.Run("An SSL cert is updated", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "dirty",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeCertificate,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(true)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.True(t, dirty)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)
	})

	t.Run("An SSL cert that isn't updated is unchanged", func(t *testing.T) {
		manifest := model.Manifest{
			Configuration: &model.Configuration{
				Variables: []*model.ConfigurationVariable{
					{
						Name:   "clean",
						Secret: true,
						Generator: &model.ConfigurationVariableGenerator{
							Type: model.GeneratorTypeCertificate,
						},
					},
				},
			},
		}

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		dirty := GenerateSecrets(manifest, &secrets, &updates)
		assert.False(t, dirty)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)
	})
}

func TestUpdateVariable(t *testing.T) {
	t.Run("NameInUpdatesButNotSecrets", func(t *testing.T) {
		t.Parallel()

		// If `name` is in updates but not secrets, the dirty flag should be set and the secret should be updated
		secrets := v1.Secret{Data: map[string][]byte{}}

		update := v1.Secret{Data: map[string][]byte{}}
		update.Data["not-in-secrets"] = []byte("value1")

		configVar := model.ConfigurationVariable{Name: "NOT_IN_SECRETS"}
		result := updateVariable(&secrets, &update, &configVar)
		assert.True(t, result)
		assert.Equal(t, "value1", string(secrets.Data["not-in-secrets"]))
	})

	t.Run("NameNotInUpdates", func(t *testing.T) {
		t.Parallel()

		// If `name` isn't in updates, don't do anything
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["not-in-updates"] = []byte("value2")

		update := v1.Secret{Data: map[string][]byte{}}

		configVar := model.ConfigurationVariable{Name: "NOT_IN_UPDATES"}
		result := updateVariable(&secrets, &update, &configVar)
		assert.False(t, result)
		assert.Equal(t, "value2", string(secrets.Data["not-in-updates"]))
	})

	t.Run("NameInUpdatesAndSecrets", func(t *testing.T) {
		t.Parallel()

		// If `name` is in secrets, don't do anything
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["in-updates"] = []byte("orig")

		update := v1.Secret{Data: map[string][]byte{}}
		update.Data["in-updates"] = []byte("changed")

		configVar := model.ConfigurationVariable{Name: "IN_UPDATES"}
		result := updateVariable(&secrets, &update, &configVar)
		assert.False(t, result)
		assert.Equal(t, "orig", string(secrets.Data["in-updates"]))
	})
}

func TestMigrateRenamedVariable(t *testing.T) {
	t.Run("NoPreviousNames", func(t *testing.T) {
		t.Parallel()

		// If `name` has no previous names, then it should remain empty and `dirty` should be false
		secrets := v1.Secret{Data: map[string][]byte{}}

		configVar := model.ConfigurationVariable{Name: "NEW_NAME"}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.False(t, result)
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithoutValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, but without value, then it should remain empty and `dirty` should be false
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("")

		configVar := model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.False(t, result)
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, then it should copy the previous value and `dirty` should be true
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")

		configVar := model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.True(t, result)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("NewValueAlreadyExists", func(t *testing.T) {
		t.Parallel()

		// If `name` has a value, then it should not be changed and `dirty` should be false
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["new-name"] = []byte("value2")

		configVar := model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.False(t, result)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNames", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first previous value and `dirty` should be true
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.True(t, result)
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNamesMissingSomeValues", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first non-empty previous value and `dirty` should be true
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		result := migrateRenamedVariable(&secrets, &configVar)
		assert.True(t, result)
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})
}
