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

const certID = "cert-id"

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

func (m *MockSSL) createCA(secrets *v1.Secret, id string) {
	m.Called(secrets, id)
}

func (m *MockSSL) createCert(secrets *v1.Secret, id string) {
	m.Called(secrets, id)
}

func TestRecordCertInfo(t *testing.T) {
	t.Run("Certificate should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        certID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "cert-name", certInfo[certID].CertificateName)
	})

	t.Run("Private key should be added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        certID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "private-key-name", certInfo[certID].PrivateKeyName)
	})

	t.Run("Private key and cert should be in the same mapped value", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        certID,
			},
		}
		RecordCertInfo(configVar)
		configVar = &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        certID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "cert-name", certInfo[certID].CertificateName)
		assert.Equal(t, "private-key-name", certInfo[certID].PrivateKeyName)
	})

	t.Run("SubjectNames are added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType:    model.ValueTypePrivateKey,
				SubjectNames: []string{"subject names"},
				ID:           certID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "subject names", certInfo[certID].SubjectNames[0])
	})

	t.Run("Rolename is added to certInfo", func(t *testing.T) {
		certInfo = make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				RoleName:  "role name",
				ID:        certID,
			},
		}
		RecordCertInfo(configVar)
		assert.Equal(t, "role name", certInfo[certID].RoleName)
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
		certInfo[certID] = CertInfo{IsAuthority: true}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		// When createCA returns true
		mockSSL.On("createCA", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCA", secrets, certID)

		// When createCA returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCA", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCA", secrets, certID)
	})

	t.Run("Check createCert is called properly when SubjectNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames > 0 and rolename is blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			SubjectNames: []string{"subject"},
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

	})

	t.Run("Check createCert is called properly when RoleName is specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If no subjectnames and the rolename is not blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			RoleName: "rolename",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

	})

	t.Run("Check createCert is called properly when SubjectNames and RoleNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames > 0 and rolename is not blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			RoleName:     "rolename",
			SubjectNames: []string{"subject"},
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)
	})

	t.Run("Check createCert is called properly when neither SubjectNames nor RoleNames specified", func(t *testing.T) {
		var mockSSL MockSSL
		createCert = mockSSL.createCert

		//
		// If subjectnames == 0 and rolename is blank, call createCert
		//
		certInfo = make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			RoleName:     "",
			SubjectNames: []string{},
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		// When createCert returns true
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)

		// When createCert returns false
		mockSSL.ExpectedCalls = nil
		mockSSL.Calls = nil
		mockSSL.On("createCert", secrets, certID)
		GenerateCerts(secrets)
		mockSSL.AssertCalled(t, "createCert", secrets, certID)
	})
}

func TestRsaKeyRequest(t *testing.T) {
	t.Parallel()

	kr := rsaKeyRequest()
	assert.Equal(t, 4096, kr.S)
}

func TestCreateCA(t *testing.T) {
	t.Run("createCA shouldn't update if PrivateKeyName is defined", func(t *testing.T) {
		//
		// If PrivateKeyName isn't blank, return false
		//
		certInfo = make(map[string]CertInfo)
		secrets := &v1.Secret{Data: map[string][]byte{}}

		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")

		createCAImpl(secrets, certID)

		assert.Equal(t, []byte("private-key-data"), certInfo[certID].PrivateKey)
		assert.Equal(t, []byte("certificate-data"), certInfo[certID].Certificate)
	})

	t.Run("createCA should generate valid data", func(t *testing.T) {
		secrets := &v1.Secret{Data: map[string][]byte{}}
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		createCAImpl(secrets, certID)
		assert.NotEqual(t, secrets.Data[certInfo[certID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[certID].CertificateName], []byte{})
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

	certInfo = make(map[string]CertInfo)
	createCAImpl(secrets, defaultCA)
	defaultCAInfo := certInfo[defaultCA]

	t.Run("If secrets has a private key, return false", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		createCertImpl(secrets, certID)
	})

	t.Run("If updateCert() is true, return true", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}

		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		createCertImpl(secrets, certID)
	})

	t.Run("If the default CA private key isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		certInfo[defaultCA] = CertInfo{
			Certificate: []byte("default-certificate"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{defaultCA})
		createCertImpl(secrets, certID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{defaultCA})

	})

	t.Run("If the default CA certificate isn't found, logFatalf", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		certInfo[defaultCA] = CertInfo{
			PrivateKey: []byte("private-key"),
		}
		mockLog.On("Fatalf",
			"CA %s not found",
			[]interface{}{defaultCA})
		createCertImpl(secrets, certID)
		mockLog.AssertCalled(t, "Fatalf",
			"CA %s not found",
			[]interface{}{defaultCA})

	})

	t.Run("If CA cert fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}

		// Create a bogus default CA
		certInfo[defaultCA] = CertInfo{
			Certificate: []byte("default-certificate"),
			PrivateKey:  []byte("private-key"),
		}
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		mockLog.On("Fatalf",
			"Cannot parse CA cert: %s",
			[]interface{}{cferr.New(1000, 2)})
		createCertImpl(secrets, certID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA cert: %s",
			[]interface{}{cferr.New(1000, 2)})

	})

	t.Run("If CA private key fails to parse, it should log a fatal error", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}

		// Invalidate the private key of the default CA
		info := defaultCAInfo
		info.PrivateKey = []byte("private-key")
		certInfo[defaultCA] = info
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		mockLog.On("Fatalf",
			"Cannot parse CA private key: %s",
			[]interface{}{cferr.New(2000, 2)})
		createCertImpl(secrets, certID)
		mockLog.AssertCalled(t, "Fatalf",
			"Cannot parse CA private key: %s",
			[]interface{}{cferr.New(2000, 2)})

	})

	t.Run("secrets.Data should have a private key and a certificate", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		secrets := &v1.Secret{Data: map[string][]byte{}}
		certInfo[defaultCA] = defaultCAInfo
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		createCertImpl(secrets, certID)
		assert.NotEqual(t, secrets.Data[certInfo[certID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[certID].CertificateName], []byte{})
		_, err := tls.X509KeyPair(secrets.Data[certInfo[certID].CertificateName],
			secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NoError(t, err)

	})

	t.Run("rolename isn't empty and the env is valid, cert should be updated", func(t *testing.T) {
		var mockLog MockLog
		logFatalf = mockLog.Fatalf

		origGetEnv := getEnv
		defer func() {
			getEnv = origGetEnv
		}()
		getEnv = func(string) string {
			return "2"
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		defer util.ClearOverrides()
		util.OverrideEnv("KUBERNETES_NAMESPACE", "namespace")
		util.OverrideEnv("KUBE_SERVICE_DOMAIN_SUFFIX", "invalid")

		certInfo[defaultCA] = defaultCAInfo
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{},
			RoleName:        "dummy-role",
		}
		createCertImpl(secrets, certID)
		assert.NotEmpty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[certID].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[certID].CertificateName])
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
