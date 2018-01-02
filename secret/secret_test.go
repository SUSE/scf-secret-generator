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

func (m *MockBase) ClearCalls() {
	m.Calls = nil
	m.ExpectedCalls = nil
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
	args := m.Called(secretData, updateData, secretName)
	return args.Bool(0)
}

func (m *MockSecrets) SSHKeyGenerate(secretData, updateData map[string][]byte, key ssh.SSHKey) bool {
	args := m.Called(secretData, updateData, key)
	return args.Bool(0)
}

func (m *MockSecrets) RecordSSHKeyInfo(keys map[string]ssh.SSHKey, configVar *model.ConfigurationVariable) {
	m.Called(keys, configVar)
	keys[configVar.Name] = ssh.SSHKey{}
}

func (m *MockSecrets) RecordSSLCertInfo(configVar *model.ConfigurationVariable) {
	m.Called(configVar)
}

func (m *MockSecrets) GenerateSSLCerts(secrets, updates *v1.Secret) (dirty bool) {
	args := m.Called(secrets, updates)
	return args.Bool(0)
}

func TestUpdateSecretsWhenCreatingOrUpdating(t *testing.T) {
	t.Parallel()

	var s MockSecretInterface
	s.On("Create", (*v1.Secret)(nil)).Return(nil, nil)
	s.On("Update", (*v1.Secret)(nil)).Return(nil, nil)

	UpdateSecrets(&s, nil, false, false)
	s.AssertNotCalled(t, "Create", nil)
	s.AssertNotCalled(t, "Update", nil)

	s.Calls = []mock.Call{}

	UpdateSecrets(&s, nil, true, false)
	s.AssertCalled(t, "Create", (*v1.Secret)(nil))
	s.AssertNotCalled(t, "Update", nil)
	s.Calls = []mock.Call{}

	UpdateSecrets(&s, nil, true, true)
	s.AssertCalled(t, "Create", (*v1.Secret)(nil))
	s.AssertNotCalled(t, "Update", (*v1.Secret)(nil))

	s.Calls = []mock.Call{}

	UpdateSecrets(&s, nil, false, true)
	s.AssertNotCalled(t, "Create", (*v1.Secret)(nil))
	s.AssertCalled(t, "Update", (*v1.Secret)(nil))
}

func TestGetOrCreateWithValidSecrets(t *testing.T) {
	t.Parallel()

	//
	// Set up mocked functions
	//
	assert := assert.New(t)

	origLogFatal := logFatal
	origGetEnv := getEnv
	defer func() {
		logFatal = origLogFatal
		getEnv = origGetEnv
	}()

	var mockLog MockLog
	logFatal = mockLog.Fatal

	// Missing secret-updates
	//   should logFatal
	var s MockSecretInterface
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
	// secret-updates with revision
	//   should append revision to secret requested
	getEnv = func(string) string {
		return "1234"
	}
	s.ClearCalls()
	mockLog.ClearCalls()
	s.On("Get", SECRET_UPDATE_NAME+"-1234", metav1.GetOptions{})
	s.On("Get", SECRET_NAME, metav1.GetOptions{})
	_, _, _ = GetOrCreateSecrets(&s)
	s.AssertCalled(t, "Get", SECRET_UPDATE_NAME+"-1234", metav1.GetOptions{})

	// Valid secret-updates
	//   should call get with SECRET_NAME
	//   should return that secret
	getEnv = func(string) string {
		return ""
	}
	s.ClearCalls()
	mockLog.ClearCalls()
	s.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
	s.On("Get", SECRET_NAME, metav1.GetOptions{})
	create, secrets, _ := GetOrCreateSecrets(&s)
	s.AssertCalled(t, "Get", SECRET_NAME, metav1.GetOptions{})
	assert.Equal(secrets.Data[SECRET_NAME], []byte(SECRET_NAME))
	assert.False(create)

	// Missing secret
	//   should return IsNotFound
	//   should create a secret
	var sMissing MockSecretInterfaceMissing
	getEnv = func(string) string {
		return ""
	}
	sMissing.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
	sMissing.On("Get", SECRET_NAME, metav1.GetOptions{})
	create, secrets, updates := GetOrCreateSecrets(&sMissing)
	assert.True(create)
	assert.NotNil(secrets)
	assert.NotNil(updates)

	// Unrelated Get error for SECRET_NAME
	//   should logFatal
	var sUnknown MockSecretInterfaceUnknown
	getEnv = func(string) string {
		return ""
	}
	mockLog.ClearCalls()
	mockLog.On("Fatal", []interface{}{errors.New("unknownerr")})
	sUnknown.On("Get", SECRET_UPDATE_NAME, metav1.GetOptions{})
	sUnknown.On("Get", SECRET_NAME, metav1.GetOptions{})
	create, secrets, updates = GetOrCreateSecrets(&sUnknown)
	mockLog.AssertCalled(t, "Fatal", []interface{}{errors.New("unknownerr")})
}

func TestGenerateSecretsWithNoSecrets(t *testing.T) {
	assert := assert.New(t)

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

	var mockSecrets MockSecrets

	passGenerate = mockSecrets.PassGenerate
	sshKeyGenerate = mockSecrets.SSHKeyGenerate
	recordSSHKeyInfo = mockSecrets.RecordSSHKeyInfo
	recordSSLCertInfo = mockSecrets.RecordSSLCertInfo
	generateSSLCerts = mockSecrets.GenerateSSLCerts

	secrets := v1.Secret{Data: map[string][]byte{}}
	updates := v1.Secret{Data: map[string][]byte{}}

	//
	// Test that a manifest with no secrets doesn't generate a change
	//
	manifest := model.Manifest{
		Configuration: &model.Configuration{Variables: []*model.ConfigurationVariable{}},
	}

	mockSecrets.On("GenerateSSLCerts", (*v1.Secret)(nil), (*v1.Secret)(nil)).Return(false)
	dirty := GenerateSecrets(manifest, nil, nil)
	assert.False(dirty)
	mockSecrets.AssertCalled(t, "GenerateSSLCerts", (*v1.Secret)(nil), (*v1.Secret)(nil))

	//
	// Test with a password that is updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("PassGenerate", map[string][]byte{}, map[string][]byte{}, "dirty").Return(true)
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.True(dirty)
	mockSecrets.AssertCalled(t, "PassGenerate", map[string][]byte{}, map[string][]byte{}, "dirty")

	//
	// Test with a password that wouldn't be updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("PassGenerate", map[string][]byte{}, map[string][]byte{}, "clean").Return(false)
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.False(dirty)
	mockSecrets.AssertCalled(t, "PassGenerate", map[string][]byte{}, map[string][]byte{}, "clean")

	//
	// Test with a non-generated, non-updated secret
	//
	manifest = model.Manifest{
		Configuration: &model.Configuration{
			Variables: []*model.ConfigurationVariable{
				{
					Name:   "non-generated",
					Secret: true,
				},
			},
		},
	}

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)

	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.False(dirty)

	//
	// Test with a non-generated, updated secret
	//
	manifest = model.Manifest{
		Configuration: &model.Configuration{
			Variables: []*model.ConfigurationVariable{
				{
					Name:   "NON_GENERATED",
					Secret: true,
				},
			},
		},
	}

	updates.Data["non-generated"] = []byte("password")

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)

	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.True(dirty)
	assert.Equal(secrets.Data["non-generated"], []byte("password"))

	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}

	//
	// Test with an SSH key that is updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
	mockSecrets.On("SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{}).Return(true)
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.True(dirty)
	mockSecrets.AssertCalled(t, "SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{})
	mockSecrets.AssertCalled(t, "RecordSSHKeyInfo", map[string]ssh.SSHKey{"dirty": ssh.SSHKey{}}, manifest.Configuration.Variables[0])

	//
	// Test with an SSH key that is *not* updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("RecordSSHKeyInfo", map[string]ssh.SSHKey{}, manifest.Configuration.Variables[0])
	mockSecrets.On("SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{}).Return(false)
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.False(dirty)
	mockSecrets.AssertCalled(t, "SSHKeyGenerate", map[string][]byte{}, map[string][]byte{}, ssh.SSHKey{})
	mockSecrets.AssertCalled(t, "RecordSSHKeyInfo", map[string]ssh.SSHKey{"clean": ssh.SSHKey{}}, manifest.Configuration.Variables[0])

	//
	// Test with an SSL CA cert that is updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(true)
	mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.True(dirty)
	mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
	mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)

	//
	// Test with an SSL CA cert that is *not* updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.False(dirty)
	mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
	mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)

	//
	// Test with an SSL cert that is updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(true)
	mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.True(dirty)
	mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
	mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)

	//
	// Test with an SSL cert that is *not* updated
	//
	manifest = model.Manifest{
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

	mockSecrets.ClearCalls()
	mockSecrets.On("GenerateSSLCerts", &secrets, &updates).Return(false)
	mockSecrets.On("RecordSSLCertInfo", manifest.Configuration.Variables[0])
	dirty = GenerateSecrets(manifest, &secrets, &updates)
	assert.False(dirty)
	mockSecrets.AssertCalled(t, "RecordSSLCertInfo", manifest.Configuration.Variables[0])
	mockSecrets.AssertCalled(t, "GenerateSSLCerts", &secrets, &updates)
}

func TestUpdateVariable(t *testing.T) {
	assert := assert.New(t)

	t.Run("NameInUpdatesButNotSecrets", func(t *testing.T) {
		t.Parallel()

		// If `name` is in updates but not secrets, the dirty flag should be set and the secret should be updated
		secrets := v1.Secret{Data: map[string][]byte{}}

		update := v1.Secret{Data: map[string][]byte{}}
		update.Data["not-in-secrets"] = []byte("value1")

		configVar := model.ConfigurationVariable{Name: "NOT_IN_SECRETS"}
		result := updateVariable(&secrets, &update, &configVar)
		assert.True(result)
		assert.Equal(string(secrets.Data["not-in-secrets"]), "value1")
	})

	t.Run("NameNotInUpdates", func(t *testing.T) {
		t.Parallel()

		// If `name` isn't in updates, don't do anything
		secrets := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["not-in-updates"] = []byte("value2")

		update := v1.Secret{Data: map[string][]byte{}}

		configVar := model.ConfigurationVariable{Name: "NOT_IN_UPDATES"}
		result := updateVariable(&secrets, &update, &configVar)
		assert.False(result)
		assert.Equal(string(secrets.Data["not-in-updates"]), "value2")
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
		assert.False(result)
		assert.Equal(string(secrets.Data["in-updates"]), "orig")
	})
}
