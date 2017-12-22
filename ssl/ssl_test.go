package ssl

import (
	"errors"
	"strconv"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/cloudflare/cfssl/csr"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	v1 "k8s.io/api/core/v1"
)

const CERT_ID = "cert-id"

type MockBase struct {
	mock.Mock
}

type MockLog struct {
	MockBase
}

func (m *MockLog) Fatalf(str string, message ...interface{}) {
	m.Called(str, message)
}

type MockSSL struct {
	MockBase
}

func (m *MockSSL) createCA(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	args := m.Called(secrets, updates, id)
	return args.Bool(0)
}

func (m *MockSSL) createCert(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	args := m.Called(secrets, updates, id)
	return args.Bool(0)
}

func (m *MockSSL) updateCert(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	args := m.Called(secrets, updates, id)
	return args.Bool(0)
}

func (m *MockBase) ClearCalls() {
	m.Calls = nil
	m.ExpectedCalls = nil
}

func TestRecordCertInfo(t *testing.T) {
	assert := assert.New(t)

	certInfo = make(map[string]CertInfo)

	//
	// Certificate is added to certInfo
	//
	configVar := model.ConfigurationVariable{
		Name:   "CERT_NAME",
		Secret: true,
		Generator: &model.ConfigurationVariableGenerator{
			ValueType: model.ValueTypeCertificate,
			ID:        CERT_ID,
		},
	}
	RecordCertInfo(&configVar)
	assert.Equal(certInfo[CERT_ID].CertificateName, "cert-name")

	//
	// PrivateKey is added to certInfo
	//
	configVar = model.ConfigurationVariable{
		Name:   "PRIVATE_KEY_NAME",
		Secret: true,
		Generator: &model.ConfigurationVariableGenerator{
			ValueType: model.ValueTypePrivateKey,
			ID:        CERT_ID,
		},
	}
	RecordCertInfo(&configVar)
	assert.Equal(certInfo[CERT_ID].PrivateKeyName, "private-key-name")

	//
	// If existing ID with certname, privatekey is added to the same CertInfo
	//
	assert.Equal(certInfo[CERT_ID].CertificateName, "cert-name")

	//
	// SubjectNames are added to certInfo
	//
	configVar = model.ConfigurationVariable{
		Name:   "PRIVATE_KEY_NAME",
		Secret: true,
		Generator: &model.ConfigurationVariableGenerator{
			ValueType:    model.ValueTypePrivateKey,
			SubjectNames: []string{"subject names"},
			ID:           CERT_ID,
		},
	}
	RecordCertInfo(&configVar)
	assert.Equal(certInfo[CERT_ID].SubjectNames[0], "subject names")

	//
	// Rolename is added to certInfo
	//
	configVar = model.ConfigurationVariable{
		Name:   "PRIVATE_KEY_NAME",
		Secret: true,
		Generator: &model.ConfigurationVariableGenerator{
			ValueType: model.ValueTypePrivateKey,
			RoleName:  "role name",
			ID:        CERT_ID,
		},
	}
	RecordCertInfo(&configVar)
	assert.Equal(certInfo[CERT_ID].RoleName, "role name")
}

func TestGenerateCerts(t *testing.T) {
	assert := assert.New(t)

	origCreateCA := createCA
	origCreateCert := createCert

	defer func() {
		createCA = origCreateCA
		createCert = origCreateCert
	}()

	var mockSSL MockSSL
	createCA = mockSSL.createCA
	createCert = mockSSL.createCert

	//
	// If no subjectnames and the rolename is blank, call createCA
	//
	certInfo = make(map[string]CertInfo)
	certInfo[CERT_ID] = CertInfo{}
	secrets := v1.Secret{Data: map[string][]byte{}}
	updates := v1.Secret{Data: map[string][]byte{}}

	// When createCA returns true
	mockSSL.On("createCA", &secrets, &updates, CERT_ID).Return(true)
	dirty := GenerateCerts(&secrets, &updates)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "createCA", &secrets, &updates, CERT_ID)

	// When createCA returns false
	mockSSL.ClearCalls()
	mockSSL.On("createCA", &secrets, &updates, CERT_ID).Return(false)
	dirty = GenerateCerts(&secrets, &updates)
	assert.False(dirty)
	mockSSL.AssertCalled(t, "createCA", &secrets, &updates, CERT_ID)

	//
	// If subjectnames > 0 and rolename is blank, call createCert
	//
	certInfo[CERT_ID] = CertInfo{
		SubjectNames: []string{"subject"},
	}

	// When createCert returns true
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
	dirty = GenerateCerts(&secrets, &updates)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	// When createCert returns false
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = GenerateCerts(&secrets, &updates)
	assert.False(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	//
	// If no subjectnames and the rolename is not blank, call createCert
	//
	certInfo[CERT_ID] = CertInfo{
		RoleName: "rolename",
	}

	// When createCert returns true
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
	dirty = GenerateCerts(&secrets, &updates)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	// When createCert returns false
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = GenerateCerts(&secrets, &updates)
	assert.False(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	//
	// If subjectnames > 0 and rolename is not blank, call createCert
	//
	certInfo[CERT_ID] = CertInfo{
		RoleName:     "rolename",
		SubjectNames: []string{"subject"},
	}

	// When createCert returns true
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
	dirty = GenerateCerts(&secrets, &updates)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	// When createCert returns false
	mockSSL.ClearCalls()
	mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = GenerateCerts(&secrets, &updates)
	assert.False(dirty)
	mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)
}

func TestRsaKeyRequest(t *testing.T) {
	assert := assert.New(t)
	kr := rsaKeyRequest()
	assert.Equal(kr.S, 4096)
}

func TestCreateCA(t *testing.T) {
	assert := assert.New(t)

	origUpdateCert := updateCert

	defer func() {
		updateCert = origUpdateCert
	}()

	var mockSSL MockSSL
	updateCert = mockSSL.updateCert

	//
	// If PrivateKeyName isn't blank, return false
	//
	certInfo = make(map[string]CertInfo)
	secrets := v1.Secret{Data: map[string][]byte{}}
	updates := v1.Secret{Data: map[string][]byte{}}

	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
	}

	secrets.Data["private-key"] = []byte("private-key-data")
	secrets.Data["certificate-name"] = []byte("certificate-data")

	dirty := createCAImpl(&secrets, &updates, CERT_ID)

	assert.False(dirty)
	assert.Equal(certInfo[CERT_ID].PrivateKey, []byte("private-key-data"))
	assert.Equal(certInfo[CERT_ID].Certificate, []byte("certificate-data"))

	//
	// If updateCert() is true, return true
	//
	certInfo = make(map[string]CertInfo)
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(true)
	dirty = createCAImpl(&secrets, &updates, CERT_ID)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "updateCert", &secrets, &updates, CERT_ID)

	//
	// Test that the certs are actually generated
	//
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
	}

	mockSSL.ClearCalls()
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = createCAImpl(&secrets, &updates, CERT_ID)
	assert.True(dirty)
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
}

func TestAddHost(t *testing.T) {
	assert := assert.New(t)

	//
	// Ensure only the host is added when wildcard is false
	//
	req := csr.CertificateRequest{}
	addHost(&req, false, "name")
	assert.Equal(req.Hosts[0], "name")
	assert.Equal(len(req.Hosts), 1)

	//
	// Ensure a wildcard is added when wildcard is true
	//
	req = csr.CertificateRequest{}
	addHost(&req, true, "name")
	assert.Equal(req.Hosts[0], "name")
	assert.Equal(req.Hosts[1], "*.name")
	assert.Equal(len(req.Hosts), 2)
}

func TestCreateCert(t *testing.T) {
	assert := assert.New(t)

	// Initialize a default CA for later use in this test
	secrets := v1.Secret{Data: map[string][]byte{}}
	updates := v1.Secret{Data: map[string][]byte{}}

	certInfo = make(map[string]CertInfo)
	createCAImpl(&secrets, &updates, DEFAULT_CA)
	defaultCA := certInfo[DEFAULT_CA]

	origLogFatalf := logFatalf
	origUpdateCert := updateCert
	defer func() {
		logFatalf = origLogFatalf
		updateCert = origUpdateCert
	}()

	var mockLog MockLog
	logFatalf = mockLog.Fatalf

	var mockSSL MockSSL
	updateCert = mockSSL.updateCert

	//
	// If secrets has a private key, return false
	//
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
	}
	secrets.Data["private-key"] = []byte("private-key-data")
	secrets.Data["certificate-name"] = []byte("certificate-data")
	dirty := createCertImpl(&secrets, &updates, CERT_ID)
	assert.False(dirty)

	//
	// If updateCert() is true, return true
	//
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
	}
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(true)
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	assert.True(dirty)
	mockSSL.AssertCalled(t, "updateCert", &secrets, &updates, CERT_ID)

	//
	// If the default CA private key isn't found, logFatalf
	//
	mockSSL.ClearCalls()
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	certInfo[DEFAULT_CA] = CertInfo{
		Certificate: []byte("default-certificate"),
	}
	mockLog.On("Fatalf",
		"CA %s not found",
		[]interface{}{DEFAULT_CA})
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"CA %s not found",
		[]interface{}{DEFAULT_CA})

	//
	// If the default CA certificate isn't found, logFatalf
	//
	mockSSL.ClearCalls()
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	certInfo[DEFAULT_CA] = CertInfo{
		PrivateKey: []byte("private-key"),
	}
	mockLog.On("Fatalf",
		"CA %s not found",
		[]interface{}{DEFAULT_CA})
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"CA %s not found",
		[]interface{}{DEFAULT_CA})

	//
	// If CA cert fails to parse, it should log a fatal error
	//
	mockSSL.ClearCalls()
	mockLog.ClearCalls()
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	// Create a bogus default CA
	certInfo[DEFAULT_CA] = CertInfo{
		Certificate: []byte("default-certificate"),
		PrivateKey:  []byte("private-key"),
	}
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
		SubjectNames:    []string{"subject-names"},
	}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	mockLog.On("Fatalf",
		"Cannot parse CA cert: %s",
		[]interface{}{cferr.New(1000, 2)})
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"Cannot parse CA cert: %s",
		[]interface{}{cferr.New(1000, 2)})

	//
	// If CA private key fails to parse, it should log a fatal error
	//
	mockSSL.ClearCalls()
	mockLog.ClearCalls()
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	// Invalidate the private key of the default CA
	info := defaultCA
	info.PrivateKey = []byte("private-key")
	certInfo[DEFAULT_CA] = info
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
		SubjectNames:    []string{"subject-names"},
	}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	mockLog.On("Fatalf",
		"Cannot parse CA private key: %s",
		[]interface{}{cferr.New(2000, 2)})
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"Cannot parse CA private key: %s",
		[]interface{}{cferr.New(2000, 2)})

	//
	// If successful, secrets.Data should have a private key and a certificate, and should return true
	//
	mockSSL.ClearCalls()
	mockLog.ClearCalls()
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	certInfo[DEFAULT_CA] = defaultCA
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
		SubjectNames:    []string{"subject-names"},
	}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	assert.True(dirty)
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})

	//
	// If the rolename isn't empty and the env can't be parsed
	//
	mockSSL.ClearCalls()
	mockLog.ClearCalls()
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
		SubjectNames:    []string{"subject-names"},
		RoleName:        "role-name",
	}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	mockLog.On("Fatalf",
		"Cannot parse %s value '%s': %s",
		[]interface{}{"KUBE_SIZING_ROLE_NAME_COUNT", "", &strconv.NumError{Func: "ParseInt",
			Num: "", Err: errors.New("invalid syntax")}})
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"Cannot parse %s value '%s': %s",
		[]interface{}{"KUBE_SIZING_ROLE_NAME_COUNT", "", &strconv.NumError{Func: "ParseInt",
			Num: "", Err: errors.New("invalid syntax")}})

	//
	// If the rolename isn't empty and the env is valid
	//
	origGetEnv := getEnv
	defer func() {
		getEnv = origGetEnv
	}()
	getEnv = func(string) string {
		return "2"
	}
	mockSSL.ClearCalls()
	mockLog.ClearCalls()
	secrets = v1.Secret{Data: map[string][]byte{}}
	updates = v1.Secret{Data: map[string][]byte{}}
	mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
	dirty = createCertImpl(&secrets, &updates, CERT_ID)
	assert.True(dirty)
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
	assert.NotEqual(secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
}

func TestUpdateCert(t *testing.T) {
	assert := assert.New(t)

	origLogFatalf := logFatalf
	defer func() {
		logFatalf = origLogFatalf
	}()

	var mockLog MockLog
	logFatalf = mockLog.Fatalf

	//
	// Test when updates.Data has a PrivateKeyName and a cert name
	//
	secrets := v1.Secret{Data: map[string][]byte{}}
	updates := v1.Secret{Data: map[string][]byte{}}
	certInfo = make(map[string]CertInfo)
	certInfo[CERT_ID] = CertInfo{
		PrivateKeyName:  "private-key",
		CertificateName: "certificate-name",
	}

	updates.Data["private-key"] = []byte("private-key-data")
	updates.Data["certificate-name"] = []byte("certificate-data")

	result := updateCertImpl(&secrets, &updates, CERT_ID)

	assert.True(result)
	assert.Equal(certInfo[CERT_ID].PrivateKey, []byte("private-key-data"))
	assert.Equal(certInfo[CERT_ID].Certificate, []byte("certificate-data"))

	//
	// If updates.Data has a PrivateKeyName but doesn't have a cert name
	// it should logFatal
	//
	updates = v1.Secret{Data: map[string][]byte{}}
	updates.Data["private-key"] = []byte("private-key-data")
	mockLog.On("Fatalf",
		"Update includes %s but not %s",
		[]interface{}{"private-key", "certificate-name"})
	result = updateCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"Update includes %s but not %s",
		[]interface{}{"private-key", "certificate-name"})

	//
	// If updates.Data doesn't have a PrivateKeyName but it has a cert name
	// it should logFatal
	//
	updates = v1.Secret{Data: map[string][]byte{}}
	updates.Data["certificate-name"] = []byte("certificate-data")
	mockLog.On("Fatalf",
		"Update includes %s but not %s",
		[]interface{}{"certificate-name", "private-key"})
	result = updateCertImpl(&secrets, &updates, CERT_ID)
	mockLog.AssertCalled(t, "Fatalf",
		"Update includes %s but not %s",
		[]interface{}{"certificate-name", "private-key"})

	//
	// When updates.Data doesn't have a PrivateKeyName or a cert name
	// it should return false
	//
	updates = v1.Secret{Data: map[string][]byte{}}
	certInfo[CERT_ID] = CertInfo{}
	result = updateCertImpl(&secrets, &updates, CERT_ID)
	assert.False(result)
}
