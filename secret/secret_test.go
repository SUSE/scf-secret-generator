package secret

import (
	"errors"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/ssh"
	"github.com/SUSE/scf-secret-generator/util"

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

type MockSecretInterfaceMany struct {
	MockSecretInterface
}

func (m *MockSecretInterface) Create(secret *v1.Secret) (*v1.Secret, error) {
	m.Called(secret)
	return nil, nil
}

func (m *MockSecretInterface) List(options metav1.ListOptions) (*v1.SecretList, error) {
	m.Called(options)
	sl := v1.SecretList {
		Items: []v1.Secret{
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bogus",
				},
				Data: map[string][]byte{},
			},
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: SECRET_NAME,
				},
				Data: map[string][]byte{},
			},
		},
	}
	sl.Items[0].Data["bogus"] = []byte("bogus")
	sl.Items[1].Data[SECRET_NAME] = []byte(SECRET_NAME)
	return &sl, nil
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

func (m *MockSecretInterfaceMissing) List(options metav1.ListOptions) (*v1.SecretList, error) {
	m.Called(options)
	sl := v1.SecretList {
		Items: []v1.Secret{
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "nothing",
				},
				Data: map[string][]byte{},
			},
		},
	}
	sl.Items[0].Data["nothing"] = []byte("nothing")
	return &sl, nil
}

func (m *MockSecretInterfaceUnknown) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
	m.Called(name, options)

	return nil, errors.New("unknownerr")
}

func (m *MockSecretInterfaceMany) Get(name string, options metav1.GetOptions) (*v1.Secret, error) {
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

func (m *MockSecretInterfaceMany) List(options metav1.ListOptions) (*v1.SecretList, error) {
	m.Called(options)
	sl := v1.SecretList {
		Items: []v1.Secret{
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "nothingness",
				},
				Data: map[string][]byte{},
			},
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: SECRET_NAME+"-1",
				},
				Data: map[string][]byte{},
			},
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "bogus",
				},
				Data: map[string][]byte{},
			},
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: SECRET_NAME+"-12",
				},
				Data: map[string][]byte{},
			},
			v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: SECRET_NAME,
				},
				Data: map[string][]byte{},
			},
		},
	}
	sl.Items[0].Data["nothingness"] = []byte("nothingness")
	sl.Items[1].Data[SECRET_NAME+"-1"] = []byte(SECRET_NAME+"-1")
	sl.Items[2].Data["bogus"] = []byte("bogus")
	sl.Items[3].Data[SECRET_NAME+"-12"] = []byte(SECRET_NAME+"-12")
	sl.Items[4].Data[SECRET_NAME] = []byte(SECRET_NAME)
	return &sl, nil
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

func TestUpdateSecretsWhenCreatingOrUpdating(t *testing.T) {
	t.Parallel()

	t.Run("Neither Create Nor Update called", func(t *testing.T) {
		t.Parallel()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}

		s.On("Create", secrets).Return(nil, nil)
		s.On("Update", secrets).Return(nil, nil)

		UpdateSecrets(&s, secrets, false)
		s.AssertNotCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
	})

	t.Run("Create, but don't update", func(t *testing.T) {
		t.Parallel()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		util.MarkAsDirty(secrets)

		s.On("Create", secrets).Return(nil, nil)
		s.On("Update", secrets).Return(nil, nil)

		UpdateSecrets(&s, secrets, true)
		s.AssertCalled(t, "Create", secrets)
		s.AssertNotCalled(t, "Update", secrets)
		assert.False(t, util.IsDirty(secrets), "Secrets should always be clean after being created")
	})

	t.Run("Update, but don't create", func(t *testing.T) {
		t.Parallel()

		var s MockSecretInterface
		secrets := &v1.Secret{Data: map[string][]byte{}}
		util.MarkAsDirty(secrets)

		s.On("Create", secrets).Return(nil, nil)
		s.On("Update", secrets).Return(nil, nil)

		UpdateSecrets(&s, secrets, false)
		s.AssertNotCalled(t, "Create", secrets)
		s.AssertCalled(t, "Update", secrets)
		assert.False(t, util.IsDirty(secrets), "Secrets should always be clean after being updated")
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
		s.On("List", metav1.ListOptions{})
		_, _, _ = GetOrCreateSecrets(&s)
		s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-1234", metav1.GetOptions{})
		s.AssertCalled(t, "List", metav1.ListOptions{})
	})

	t.Run("Valid secret-updates should call List and return the SECRET_NAME secret", func(t *testing.T) {
		var s MockSecretInterface
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		s.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		s.On("Get", SECRET_NAME, metav1.GetOptions{})
		s.On("List", metav1.ListOptions{})
		create, secrets, _ := GetOrCreateSecrets(&s)
		s.AssertCalled(t, "List", metav1.ListOptions{})
		assert.Equal(t, []byte(SECRET_NAME), secrets.Data[SECRET_NAME], "Mocked secrets contain their name as a secret value")
		assert.False(t, create, "The create flag is not set when the secret already exists")
	})

	t.Run("Valid secret-updates with revision should call List and return the best-revision SECRET_NAME secret", func(t *testing.T) {
		var sMany MockSecretInterfaceMany
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return "15"
		}
		sMany.On("Get", SECRET_UPDATE_NAME+"-15", metav1.GetOptions{})
		sMany.On("List", metav1.ListOptions{})
		create, secrets, _ := GetOrCreateSecrets(&sMany)
		sMany.AssertCalled(t, "List", metav1.ListOptions{})
		assert.Equal(t, SECRET_NAME+"-15", secrets.Name, "GetOrCreate bumps the secret name to the new version to make")
		assert.Equal(t, SECRET_NAME+"-12", string(secrets.Data[SECRET_NAME+"-12"]), "Mocked secrets contain their name as a secret value")
		assert.True(t, create, "The create flag is set when a versioned secret already exists")
	})

	t.Run("Missing secret should return IsNotFound and create a secret", func(t *testing.T) {
		var sMissing MockSecretInterfaceMissing
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		sMissing.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		sMissing.On("List", metav1.ListOptions{})
		create, secrets, updates := GetOrCreateSecrets(&sMissing)
		assert.True(t, create)
		assert.NotNil(t, secrets)
		assert.NotNil(t, updates)
	})

	t.Run("Unrelated Get error for SECRET_UPDATE_NAME should logFatal", func(t *testing.T) {
		var sUnknown MockSecretInterfaceUnknown
		var mockLog MockLog
		logFatal = mockLog.Fatal

		getEnv = func(string) string {
			return ""
		}
		mockLog.On("Fatal", []interface{}{errors.New("unknownerr")})
		sUnknown.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
		//sUnknown.On("Get", SECRET_NAME, metav1.GetOptions{})
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

		// If `name` is in updates but not secrets, the dirty flag should be set and the secret should be updated
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

		// If `name` has no previous names, then it should remain empty and `dirty` should be false
		secrets := &v1.Secret{Data: map[string][]byte{}}

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME"}
		migrateRenamedVariable(secrets, configVar)
		assert.False(t, util.IsDirty(secrets))
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithoutValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, but without value, then it should remain empty and `dirty` should be false
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.False(t, util.IsDirty(secrets))
		assert.Empty(t, string(secrets.Data["new-name"]))
	})

	t.Run("PreviousNameWithValue", func(t *testing.T) {
		t.Parallel()

		// If `name` has a previous name, then it should copy the previous value and `dirty` should be true
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.True(t, util.IsDirty(secrets))
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("NewValueAlreadyExists", func(t *testing.T) {
		t.Parallel()

		// If `name` has a value, then it should not be changed and `dirty` should be false
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["new-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.False(t, util.IsDirty(secrets))
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNames", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first previous value and `dirty` should be true
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-name"] = []byte("value1")
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.True(t, util.IsDirty(secrets))
		assert.Equal(t, "value1", string(secrets.Data["new-name"]))
	})

	t.Run("MultiplePreviousNamesMissingSomeValues", func(t *testing.T) {
		t.Parallel()

		// If `name` has multiple previous names, then it should copy the first non-empty previous value and `dirty` should be true
		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["previous-previous-name"] = []byte("value2")

		configVar := &model.ConfigurationVariable{Name: "NEW_NAME", PreviousNames: []string{"PREVIOUS_NAME", "PREVIOUS_PREVIOUS_NAME"}}
		migrateRenamedVariable(secrets, configVar)
		assert.True(t, util.IsDirty(secrets))
		assert.Equal(t, "value2", string(secrets.Data["new-name"]))
	})
}
