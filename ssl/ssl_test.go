package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
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

func (m *MockSSL) createCA(secrets, updates *v1.Secret, id string) {
	m.Called(secrets, updates, id)
}

func (m *MockSSL) createCert(secrets, updates *v1.Secret, id string) {
	m.Called(secrets, updates, id)
}

func (m *MockSSL) updateCert(secrets, updates *v1.Secret, id string) bool {
	results := m.Called(secrets, updates, id)
	return results.Bool(0)
}

func TestRecordCertInfo(t *testing.T) {
	t.Run("Certificate should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "cert-name", certInfo[CERT_ID].CertificateName)
	})

	t.Run("Private key should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "private-key-name", certInfo[CERT_ID].PrivateKeyName)
	})

	t.Run("Private key and cert should be in the same mapped value", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		configVar = &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "cert-name", certInfo[CERT_ID].CertificateName)
		assert.Equal(t, "private-key-name", certInfo[CERT_ID].PrivateKeyName)
	})

	t.Run("SubjectNames are added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType:    model.ValueTypePrivateKey,
				SubjectNames: []string{"subject names"},
				ID:           CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "subject names", certInfo[CERT_ID].SubjectNames[0])
	})

	t.Run("Rolename is added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				RoleName:  "role name",
				ID:        CERT_ID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "role name", certInfo[CERT_ID].RoleName)
	})
}

func TestGenerateCerts(t *testing.T) {
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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// When createCA returns true
		mockSSL.On("createCA", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCA", secrets, updates, CERT_ID)

		// When createCA returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCA", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCA", secrets, updates, CERT_ID)
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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)
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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, updates, CERT_ID)
		GenerateCerts(secrets, updates)
		mockSSL.AssertCalled(t, "createCert", secrets, updates, CERT_ID)
	})
}

func TestRsaKeyRequest(t *testing.T) {
	t.Parallel()

	kr := rsaKeyRequest()
	assert.Equal(t, 4096, kr.S)
}

func TestCreateCA(t *testing.T) {
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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")

		createCAImpl(secrets, updates, CERT_ID)

		assert.Equal(t, []byte("private-key-data"), certInfo[CERT_ID].PrivateKey)
		assert.Equal(t, []byte("certificate-data"), certInfo[CERT_ID].Certificate)
	})

	t.Run("createCA should trigger an update if updateCert returns true", func(t *testing.T) {
		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		//
		// If updateCert() is true, return true
		//
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		certInfo = make(map[string]CertInfo)
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(true)
		createCAImpl(secrets, updates, CERT_ID)
		mockSSL.AssertCalled(t, "updateCert", secrets, updates, CERT_ID)
	})

	t.Run("createCA should generate valid data", func(t *testing.T) {
		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		createCAImpl(secrets, updates, CERT_ID)
		assert.NotEqual(t, secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
	})
}

func TestAddHost(t *testing.T) {
	t.Parallel()

	t.Run("Only host is added when wildcard is false", func(t *testing.T) {
		req := &csr.CertificateRequest{}
		addHost(req, false, "name")
		assert.Equal(t, "name", req.Hosts[0])
		assert.Len(t, req.Hosts, 1)
	})

	t.Run("Wildcard entry is added when wildcard is false", func(t *testing.T) {
		req := &csr.CertificateRequest{}
		addHost(req, true, "name")
		assert.Equal(t, "name", req.Hosts[0])
		assert.Equal(t, "*.name", req.Hosts[1])
		assert.Len(t, req.Hosts, 2)
	})
}

func TestCreateCert(t *testing.T) {
	// Initialize a default CA for later use in this test
	secrets := &v1.Secret{Data: map[string][]byte{}}
	updates := &v1.Secret{Data: map[string][]byte{}}

	certInfo = make(map[string]CertInfo)
	createCAImpl(secrets, updates, DEFAULT_CA)
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

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		createCertImpl(secrets, updates, CERT_ID)
	})

	t.Run("If updateCert() is true, return true", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(true)
		createCertImpl(secrets, updates, CERT_ID)
		mockSSL.AssertCalled(t, "updateCert", secrets, updates, CERT_ID)
	})

	t.Run("If the default CA private key isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		certInfo[DEFAULT_CA] = CertInfo{
			Certificate: []byte("default-certificate"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})
		createCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})

	})

	t.Run("If the default CA certificate isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		certInfo[DEFAULT_CA] = CertInfo{
			PrivateKey: []byte("private-key"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})
		createCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{DEFAULT_CA})

	})

	t.Run("If CA cert fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

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
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		mockLog.On("Fatalf",
			"Cannot parse CA cert: %s",
			[]interface{}{cferr.New(1000, 2)})
		createCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA cert: %s",
			[]interface{}{cferr.New(1000, 2)})

	})

	t.Run("If CA private key fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		// Invalidate the private key of the default CA
		info := defaultCA
		info.PrivateKey = []byte("private-key")
		certInfo[DEFAULT_CA] = info
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		mockLog.On("Fatalf",
			"Cannot parse CA private key: %s",
			[]interface{}{cferr.New(2000, 2)})
		createCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA private key: %s",
			[]interface{}{cferr.New(2000, 2)})

	})

	t.Run("secrets.Data should have a private key and a certificate", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		var mockSSL MockSSL
		updateCert = mockSSL.updateCert

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		certInfo[DEFAULT_CA] = defaultCA
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		createCertImpl(secrets, updates, CERT_ID)
		assert.NotEqual(t, secrets.Data[certInfo[CERT_ID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[CERT_ID].CertificateName], []byte{})
		_, err := tls.X509KeyPair(secrets.Data[certInfo[CERT_ID].CertificateName],
			secrets.Data[certInfo[CERT_ID].PrivateKeyName])
		assert.NoError(t, err)

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
		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}

		defer util.ClearOverrides()
		util.OverrideEnv("KUBERNETES_NAMESPACE", "namespace")
		util.OverrideEnv("KUBE_SERVICE_DOMAIN_SUFFIX", "invalid")

		certInfo[DEFAULT_CA] = defaultCA
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{},
			RoleName:        "dummy-role",
		}
		mockSSL.On("updateCert", secrets, updates, CERT_ID).Return(false)
		createCertImpl(secrets, updates, CERT_ID)
		assert.NotEmpty(t, secrets.Data[certInfo[CERT_ID].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[CERT_ID].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[CERT_ID].CertificateName])
		if !assert.NotNil(t, certBlob, "Failed to decode certificate PEM block") {
			return
		}
		cert, err := x509.ParseCertificate(certBlob.Bytes)
		if assert.NoError(t, err) {
			assert.Contains(t, cert.DNSNames, "dummy-role.namespace.svc.cluster.local")
			assert.Contains(t, cert.DNSNames, "*.dummy-role-set.namespace.svc.cluster.local")
			assert.Contains(t, cert.DNSNames, "dummy-role.invalid")
			assert.NotContains(t, cert.DNSNames, "dummy-role-set")
			assert.NotContains(t, cert.DNSNames, "*.*.dummy-role-set")
		}
	})
}

func TestUpdateCert(t *testing.T) {
	origLogFatalf := logFatalf
	defer func() {
		logFatalf = origLogFatalf
	}()

	t.Run("When updates.Data has a PrivateKeyName and a cert name, keep it", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		certInfo = make(map[string]CertInfo)
		certInfo[CERT_ID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		updates.Data["private-key"] = []byte("private-key-data")
		updates.Data["certificate-name"] = []byte("certificate-data")

		result := updateCertImpl(secrets, updates, CERT_ID)

		assert.True(t, result)
		assert.Equal(t, []byte("private-key-data"), certInfo[CERT_ID].PrivateKey)
		assert.Equal(t, []byte("certificate-data"), certInfo[CERT_ID].Certificate)
	})

	t.Run("If updates.Data has a PrivateKeyName but doesn't have a cert name, logFatal", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		updates.Data["private-key"] = []byte("private-key-data")
		mockLog.On("Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"private-key", "certificate-name"})
		_ = updateCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"private-key", "certificate-name"})

	})

	t.Run("If updates.Data doesn't have a PrivateKeyName but it has a cert name, logFatal", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		updates.Data["certificate-name"] = []byte("certificate-data")
		mockLog.On("Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"certificate-name", "private-key"})
		_ = updateCertImpl(secrets, updates, CERT_ID)
		mockLog.AssertCalled(t, "Fatalf",
			"Update includes %s but not %s",
			[]interface{}{"certificate-name", "private-key"})

	})

	t.Run("When updates.Data doesn't have a PrivateKeyName or a cert name, return false", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		updates := &v1.Secret{Data: map[string][]byte{}}
		certInfo[CERT_ID] = CertInfo{}
		result := updateCertImpl(secrets, updates, CERT_ID)
		assert.False(t, result)
	})
}
