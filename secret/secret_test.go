package secret

import (
	"errors"
	"strconv"
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

func (m *MockSecretInterface) Delete(name string, options *metav1.DeleteOptions) error {
	m.Called(name, options)
	return nil
}

func (m *MockSecretInterface) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	if name == SECRET_UPDATE_NAME+"-1" {
		return nil, errors.New("missing")
	} else	if name == SECRET_NAME+"-2" {
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
	// (*missing*)
	m.Called(name, options)

	if name == SECRET_NAME {
		// (*missing--a*)
		resource := schema.GroupResource{}
		return nil, k8serrors.NewNotFound(resource, "")
	} else if name == SECRET_NAME+"-2" {
		// (*missing--b*)
		resource := schema.GroupResource{}
		return nil, k8serrors.NewNotFound(resource, "")
	} else {
		// (*missing--c*)
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

func (m *MockSecrets) PassGenerate(secrets, updates *v1.Secret, secretName string) {
	m.Called(secrets, updates, secretName)
}

func (m *MockSecrets) SSHKeyGenerate(secrets, updates *v1.Secret, key ssh.SSHKey) {
	m.Called(secrets, updates, key)
}

func (m *MockSecrets) RecordSSHKeyInfo(keys map[string]ssh.SSHKey, configVar *model.ConfigurationVariable) {
	m.Called(keys, configVar)
	keys[configVar.Name] = ssh.SSHKey{}
}

func (m *MockSecrets) RecordSSLCertInfo(configVar *model.ConfigurationVariable) {
	m.Called(configVar)
}

func (m *MockSecrets) GenerateSSLCerts(secrets, updates *v1.Secret) {
	m.Called(secrets, updates)
}

func TestUpdateSecrets(t *testing.T) {
	t.Parallel()

	var s MockSecretInterface
	secrets := &v1.Secret{Data: map[string][]byte{}}

	s.On("Create", secrets).Return(nil, nil)
	s.On("Update", secrets).Return(nil, nil)

	UpdateSecrets(&s, secrets)

	s.AssertCalled(t, "Create", secrets)
	s.AssertNotCalled(t, "Update", secrets)
}

func TestCreateWithValidSecrets(t *testing.T) {
	origLogFatal := logFatal
	origGetEnv := getEnv
	defer func() {
		logFatal = origLogFatal
		getEnv = origGetEnv
	}()

	t.Run("Missing RELEASE_VERSION should logFatal", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// RELEASE_VERSION
			return ""
		}

		mockLog.On("Fatal", []interface{}{"RELEASE_REVISION is missing or empty."})
		s.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})

		_, _ = CreateSecrets(&s)

		s.AssertNotCalled(t, "Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.AssertNotCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
		mockLog.AssertCalled(t, "Fatal", []interface{}{"RELEASE_REVISION is missing or empty."})
	})

	t.Run("Non-integer RELEASE_VERSION should logFatal", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(ev string) string {
			// RELEASE_VERSION
			return "foo"
		}

		invalidSyntaxError := strconv.NumError{
			Func: "Atoi",
			Num: "foo",
			Err: errors.New("invalid syntax"),
		}

		mockLog.On("Fatal", []interface{}{&invalidSyntaxError})
		s.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})

		_, _ = CreateSecrets(&s)

		s.AssertNotCalled(t, "Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.AssertNotCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
		mockLog.AssertCalled(t, "Fatal", []interface{}{&invalidSyntaxError})
	})

	t.Run("Missing `secret-updates` should logFatal", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			// RELEASE_VERSION
			return "1"
		}

		mockLog.On("Fatal", []interface{}{errors.New("missing")})
		s.On("Get", SECRET_UPDATE_NAME+"-1", metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})

		_, _ = CreateSecrets(&s)

		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-1", metav1.GetOptions{})
		s.AssertNotCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
		mockLog.AssertCalled(t, "Fatal", []interface{}{errors.New("missing")})
	})

	t.Run("Valid secret-updates should append revision to the secrets requested, call Get and return the SECRET_NAME", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			// RELEASE_VERSION
			return "2"
		}

		// Delete will not be called in this context (rv == 2).

		s.On("Get", SECRET_UPDATE_NAME+"-2", metav1.GetOptions{})
		s.On("Get", SECRET_NAME+"-1", metav1.GetOptions{})

		secrets, _ := CreateSecrets(&s)

		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-2", metav1.GetOptions{})
		s.AssertCalled(t, "Get", SECRET_NAME+"-1", metav1.GetOptions{})
		s.AssertNotCalled(t, "Delete", SECRET_UPDATE_NAME+"-0", &metav1.DeleteOptions{})

		assert.Equal(t, []byte(SECRET_NAME+"-1"), secrets.Data[SECRET_NAME+"-1"],
			"Mocked secrets contain their name as a secret value")
	})

	t.Run("Should fall back to plain SECRET_NAME when no versioned SECRET_NAME available", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			// RELEASE_VERSION
			return "3"
		}

		s.On("Get", SECRET_UPDATE_NAME+"-3", metav1.GetOptions{})
		s.On("Delete", SECRET_NAME+"-1", &metav1.DeleteOptions{})
		s.On("Get", SECRET_NAME+"-2", metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})

		secrets, _ := CreateSecrets(&s)

		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-3", metav1.GetOptions{})
		s.AssertCalled(t, "Delete", SECRET_NAME+"-1", &metav1.DeleteOptions{})
		s.AssertCalled(t, "Get", SECRET_NAME+"-2", metav1.GetOptions{})
		s.AssertCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})

		assert.Equal(t, []byte(SECRET_NAME), secrets.Data[SECRET_NAME],
			"Mocked secrets contain their name as a secret value")
	})

	t.Run("Missing secret (neither versioned nor unversioned) should create a secret", func(t *testing.T) {
		var sMissing MockSecretInterfaceMissing
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			// RELEASE_VERSION
			return "3"
		}

		// See (*missing*) for the relevant implementation of Get

		sMissing.On("Get", SECRET_UPDATE_NAME+"-3", metav1.GetOptions{})
		// Found (*missing--c*)
		sMissing.On("Delete", SECRET_NAME+"-1", &metav1.DeleteOptions{})
		// Attempted, ok/error ignored
		sMissing.On("Get", SECRET_NAME+"-2", metav1.GetOptions{})
		// Not found (*missing--a*)
		sMissing.On("Get", SECRET_NAME, metav1.GetOptions{})
		// Not found (*missing--b*)

		secrets, updates := CreateSecrets(&sMissing)

		assert.NotNil(t, secrets)
		assert.NotNil(t, updates)
	})

	t.Run("Unrelated Get error for SECRET_UPDATE_NAME should logFatal", func(t *testing.T) {
		var sUnknown MockSecretInterfaceUnknown
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return "1"
		}

		mockLog.On("Fatal", []interface{}{errors.New("unknownerr")})
		sUnknown.On("Get", SECRET_UPDATE_NAME+"-1", metav1.GetOptions{})

		_, _ = CreateSecrets(&sUnknown)

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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		passGenerate = mockSecrets.PassGenerate
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("PassGenerate", secrets, updates, "dirty")
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "PassGenerate", secrets, updates, "dirty")
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		passGenerate = mockSecrets.PassGenerate
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("PassGenerate", secrets, updates, "clean")

		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "PassGenerate", secrets, updates, "clean")
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", secrets, updates)

		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertNotCalled(t, "GenerateSSLCerts", secrets, updates, "clean")
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		updates.Data["non-generated"] = []byte("password")

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", secrets, updates)

		GenerateSecrets(manifest, secrets, updates)
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSHKeyInfo = mockSecrets.RecordSSHKeyInfo
		sshKeyGenerate = mockSecrets.SSHKeyGenerate
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
		mockSecrets.On("SSHKeyGenerate", secrets, updates, ssh.SSHKey{}).Return(true)
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "SSHKeyGenerate", secrets, updates, ssh.SSHKey{})
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		recordSSHKeyInfo = mockSecrets.RecordSSHKeyInfo
		sshKeyGenerate = mockSecrets.SSHKeyGenerate
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
		mockSecrets.On("SSHKeyGenerate", secrets, updates, ssh.SSHKey{}).Return(false)
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "SSHKeyGenerate", secrets, updates, ssh.SSHKey{})
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", secrets, updates)
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", secrets, updates)
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", secrets, updates)
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		var mockSecrets MockSecrets
		generateSSLCerts = mockSecrets.GenerateSSLCerts
		recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
		mockSecrets.On("GenerateSSLCerts", secrets, updates)
		mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
		GenerateSecrets(manifest, secrets, updates)
		mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
		mockSecrets.AssertCalled(t, "GenerateSSLCerts", secrets, updates)
	})
}

func TestUpdateVariable(t *testing.T) {
	t.Run("NameInUpdatesButNotSecrets", func(t *testing.T) {
		t.Parallel()

		// If `name` is in updates but not secrets, the secret should be updated
		secrets := &v1.Secret{Data: map[string][]byte{}}

		update := &v1.Secret{Data: map[string][]byte{}}
		update.Data["not-in-secrets"] = []byte("value1")

		configVar := &model.ConfigurationVariable{Name: "NOT_IN_SECRETS"}
		updateVariable(secrets, update, configVar)
		assert.Equal(t, "value1", string(secrets.Data["not-in-secrets"]))
	})

	t.Run("NameNotInUpdates", func(t *testing.T) {
		t.Parallel()

		// If `name` isn't in updates, don't do anything
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["not-in-updates"] = []byte("value2")

		update := &v1.Secret{Data: map[string][]byte{}}

		configVar := &model.ConfigurationVariable{Name: "NOT_IN_UPDATES"}
		updateVariable(secrets, update, configVar)
		assert.Equal(t, "value2", string(secrets.Data["not-in-updates"]))
	})

	t.Run("NameInUpdatesAndSecrets", func(t *testing.T) {
		t.Parallel()

		// If `name` is in secrets, don't do anything
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["in-updates"] = []byte("orig")

		update := &v1.Secret{Data: map[string][]byte{}}
		update.Data["in-updates"] = []byte("changed")

		configVar := &model.ConfigurationVariable{Name: "IN_UPDATES"}
		updateVariable(secrets, update, configVar)
		assert.Equal(t, "orig", string(secrets.Data["in-updates"]))
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
