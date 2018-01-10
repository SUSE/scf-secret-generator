package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	results := m.Called(secrets, updates, id)
	return results.Bool(0)
}

func (m *MockSSL) createCert(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	results := m.Called(secrets, updates, id)
	return results.Bool(0)
}

func (m *MockSSL) updateCert(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	results := m.Called(secrets, updates, id)
	return results.Bool(0)
}

func TestRecordCertInfo(t *testing.T) {
	assert := assert.New(t)

	t.Run("Certificate should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

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
	})

	t.Run("Private key should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(&configVar)
		assert.Equal(certInfo[CERT_ID].PrivateKeyName, "private-key-name")
	})

	t.Run("Private key and cert should be in the same mapped value", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(&configVar)
		configVar = model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(&configVar)
		assert.Equal(certInfo[CERT_ID].CertificateName, "cert-name")
		assert.Equal(certInfo[CERT_ID].PrivateKeyName, "private-key-name")
	})

	t.Run("SubjectNames are added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := model.ConfigurationVariable{
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
	})

	t.Run("Rolename is added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := model.ConfigurationVariable{
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
	})
}

func TestGenerateCerts(t *testing.T) {
	assert := assert.New(t)

	origCreateCA := createCA
	origCreateCert := createCert

	defer func() {
		createCA = origCreateCA
		createCert = origCreateCert
	}()

	t.Run("Check createCA is called properly", func(t *testing.T) {
		var mockSSL MockSSL
		createCA = mockSSL.createCA

		//
		// Call createCA for CA certificates
		//
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{IsAuthority: true}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		// When createCA returns true
		mockSSL.On("createCA", &secrets, &updates, CERT_ID).Return(true)
		dirty := GenerateCerts(&secrets, &updates)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "createCA", &secrets, &updates, CERT_ID)

		// When createCA returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCA", &secrets, &updates, CERT_ID).Return(false)
		dirty = GenerateCerts(&secrets, &updates)
		assert.False(dirty)
		mockSSL.AssertCalled(t, "createCA", &secrets, &updates, CERT_ID)
	})

	t.Run("Check createCert is called properly when SubjectNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames > 0 and rolename is blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{
			SubjectNames: []string{"subject"},
		}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := GenerateCerts(&secrets, &updates)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
		dirty = GenerateCerts(&secrets, &updates)
		assert.False(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	})

	t.Run("Check createCert is called properly when RoleName is specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If no subjectnames and the rolename is not blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{
			RoleName: "rolename",
		}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := GenerateCerts(&secrets, &updates)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
		dirty = GenerateCerts(&secrets, &updates)
		assert.False(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

	})

	t.Run("Check createCert is called properly when SubjectNames and RoleNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames > 0 and rolename is not blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{
			RoleName:     "rolename",
			SubjectNames: []string{"subject"},
		}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := GenerateCerts(&secrets, &updates)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
		dirty = GenerateCerts(&secrets, &updates)
		assert.False(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)
	})

	t.Run("Check createCert is called properly when neither SubjectNames nor RoleNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames == 0 and rolename is blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{
			RoleName:     "",
			SubjectNames: []string{},
		}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := GenerateCerts(&secrets, &updates)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", &secrets, &updates, CERT_ID).Return(false)
		dirty = GenerateCerts(&secrets, &updates)
		assert.False(dirty)
		mockSSL.AssertCalled(t, "createCert", &secrets, &updates, CERT_ID)
	})
}

func TestRsaKeyRequest(t *testing.T) {
	t.Parallel()

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

	t.Run("createCA shouldn't update if PrivateKeyName is defined", func(t *testing.T) {
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
	})

	t.Run("createCA should trigger an update if updateCert returns true", func(t *testing.T) {
		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		//
		// If updateCert() is true, return true
		//
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		certInfo = make(map[string]CertInfo)
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := createCAImpl(&secrets, &updates, CERT_ID)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "updateCert", &secrets, &updates, CERT_ID)
	})

	t.Run("createCA should generate valid data", func(t *testing.T) {
		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
		dirty := createCAImpl(&secrets, &updates, CERT_ID)
		assert.True(dirty)
		assert.NotEqual(secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
		assert.NotEqual(secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
	})
}

func TestAddHost(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	t.Run("Only host is added when wildcard is false", func(t *testing.T) {
		req := csr.CertificateRequest{}
		addHost(&req, false, "name")
		assert.Equal(req.Hosts[0], "name")
		assert.Equal(len(req.Hosts), 1)
	})

	t.Run("Wildcard entry is added when wildcard is false", func(t *testing.T) {
		req := csr.CertificateRequest{}
		addHost(&req, true, "name")
		assert.Equal(req.Hosts[0], "name")
		assert.Equal(req.Hosts[1], "*.name")
		assert.Equal(len(req.Hosts), 2)
	})
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

	t.Run("If secrets has a private key, return false", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		dirty := createCertImpl(&secrets, &updates, CERT_ID)
		assert.False(dirty)
	})

	t.Run("If updateCert() is true, return true", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(true)
		dirty := createCertImpl(&secrets, &updates, CERT_ID)
		assert.True(dirty)
		mockSSL.AssertCalled(t, "updateCert", &secrets, &updates, CERT_ID)

	})

	t.Run("If the default CA private key isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
		certInfo[DEFAULT_CA] = CertInfo{
			Certificate: []byte("default-certificate"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})
		_ = createCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})

	})

	t.Run("If the default CA certificate isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
		certInfo[DEFAULT_CA] = CertInfo{
			PrivateKey: []byte("private-key"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})
		_ = createCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})

	})

	t.Run("If CA cert fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

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
		_ = createCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA cert: %s",
			[]interface{}{cferr.New(1000, 2)})

	})

	t.Run("If CA private key fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

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
		_ = createCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA private key: %s",
			[]interface{}{cferr.New(2000, 2)})

	})

	t.Run("secrets.Data should have a private key and a certificate", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		certInfo[DEFAULT_CA] = defaultCA
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
		dirty := createCertImpl(&secrets, &updates, CERT_ID)
		assert.True(dirty)
		assert.NotEqual(secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
		assert.NotEqual(secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
		_, err := tls.X509KeyPair(secrets.Data[certInfo[CERT_ID].CertificateName],
			secrets.Data[certInfo[CERT_ID].PrivateKeyName])
		assert.NoError(err)

	})

	t.Run("rolename isn't empty and the env is valid, cert should be updated", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		origGetEnv := getEnv
		defer func() {
			getEnv = origGetEnv
		}()
		getEnv = func(string) string {
			return "2"
		}
		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}

		certInfo[DEFAULT_CA] = defaultCA
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{},
			RoleName:        "dummy-role",
		}
		mockSSL.On("updateCert", &secrets, &updates, CERT_ID).Return(false)
		dirty := createCertImpl(&secrets, &updates, CERT_ID)
		assert.True(dirty)
		assert.NotEmpty(secrets.Data[certInfo[CERT_ID].PrivateKeyName])
		assert.NotEmpty(secrets.Data[certInfo[CERT_ID].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[CERT_ID].CertificateName])
		if !assert.NotNil(certBlob, "Failed to decode certificate PEM block") {
			return
		}
		cert, err := x509.ParseCertificate(certBlob.Bytes)
		if assert.NoError(err) {
			assert.Contains(cert.DNSNames, "dummy-role.<no value>.svc.cluster.local")
			assert.Contains(cert.DNSNames, "*.dummy-role-set.<no value>.svc.cluster.local")
			assert.Contains(cert.DNSNames, "dummy-role.<no value>")
			assert.NotContains(cert.DNSNames, "dummy-role-set")
			assert.NotContains(cert.DNSNames, "*.*.dummy-role-set")
		}
	})
}

func TestUpdateCert(t *testing.T) {
	assert := assert.New(t)

	origLogFatalf := logFatalf
	defer func() {
		logFatalf = origLogFatalf
	}()

	t.Run("When updates.Data has a PrivateKeyName and a cert name, keep it", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

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
	})

	t.Run("If updates.Data has a PrivateKeyName but doesn't have a cert name, logFatal", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		updates.Data["private-key"] = []byte("private-key-data")
		mockLog.On("Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"private-key", "certificate-name"})
		_ = updateCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"private-key", "certificate-name"})

	})

	t.Run("If updates.Data doesn't have a PrivateKeyName but it has a cert name, logFatal", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		updates.Data["certificate-name"] = []byte("certificate-data")
		mockLog.On("Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"certificate-name", "private-key"})
		_ = updateCertImpl(&secrets, &updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"certificate-name", "private-key"})

	})

	t.Run("When updates.Data doesn't have a PrivateKeyName or a cert name, return false", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := v1.Secret{Data: map[string][]byte{}}
		updates := v1.Secret{Data: map[string][]byte{}}
		certInfo[CERT_ID] = CertInfo{}
		result := updateCertImpl(&secrets, &updates, CERT_ID)
		assert.False(result)
	})
}
