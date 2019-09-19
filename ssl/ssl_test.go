package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/cloudflare/cfssl/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const defaultCA = "cacert"
const certID = "cert-id"

type MockBase struct {
	mock.Mock
}

type MockCertificateSigningRequestInterface struct {
	MockBase
	getCount int
}

func (m *MockCertificateSigningRequestInterface) Create(csr *certificates.CertificateSigningRequest) (*certificates.CertificateSigningRequest, error) {
	m.Called(csr)
	return csr, nil
}

func (m *MockCertificateSigningRequestInterface) Delete(name string, options *metav1.DeleteOptions) error {
	m.Called(name, options)
	return nil
}

func (m *MockCertificateSigningRequestInterface) Get(name string, options metav1.GetOptions) (*certificates.CertificateSigningRequest, error) {
	m.Called(name, options)
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certificates.CertificateSigningRequestSpec{
			Request: []byte("some-request"),
			Usages:  []certificates.KeyUsage{certificates.UsageClientAuth, certificates.UsageServerAuth},
		},
	}
	if name == "Failed" {
		return csr, errors.New("Something went wrong")
	}

	m.getCount++
	if (name == string(certificates.CertificateApproved) || name == string(certificates.CertificateDenied)) && m.getCount > 1 {
		csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
			Type: certificates.RequestConditionType("bogus"),
		})
		csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
			Type:    certificates.RequestConditionType(name),
			Reason:  "because, why not?",
			Message: "Seriously!",
		})
		if name == string(certificates.CertificateApproved) {
			csr.Status.Certificate = []byte("shiny")
		}
	}
	return csr, nil
}

func (m *MockCertificateSigningRequestInterface) UpdateApproval(csr *certificates.CertificateSigningRequest) (*certificates.CertificateSigningRequest, error) {
	m.Called(csr)
	return csr, nil
}

func TestRecordCertInfo(t *testing.T) {
	t.Parallel()

	t.Run("Certificate should be added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name:      certID,
			Type:      model.VariableTypeCertificate,
			CVOptions: model.CVOptions{Secret: true},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)
		assert.Equal(t, "cert-id", certInfo[certID].CertificateName)
	})

	t.Run("Private key should be added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name:      certID,
			Type:      model.VariableTypeCertificate,
			CVOptions: model.CVOptions{Secret: true},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)
		assert.Equal(t, "cert-id-key", certInfo[certID].PrivateKeyName)
	})

	t.Run("Private key and cert should be in the same mapped value", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name:      certID,
			Type:      model.VariableTypeCertificate,
			CVOptions: model.CVOptions{Secret: true},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)

		require.NoError(t, err)
		assert.Equal(t, "cert-id", certInfo[certID].CertificateName)
		assert.Equal(t, "cert-id-key", certInfo[certID].PrivateKeyName)
	})

	t.Run("SubjectNames are added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name: certID,
			Type: model.VariableTypeCertificate,
			Options: model.VariableOptions{
				"alternative_names": []string{"subject names"},
			},
			CVOptions: model.CVOptions{Secret: true},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)
		assert.Equal(t, "subject names", certInfo[certID].SubjectNames[0])
	})

	t.Run("Rolename is added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name: certID,
			Type: model.VariableTypeCertificate,
			CVOptions: model.CVOptions{
				Secret:   true,
				RoleName: "role name",
			},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)
		assert.Equal(t, "role name", certInfo[certID].RoleName)
	})

	t.Run("SubjectNames not allowed on CA certs", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name: "CERT_NAME",
			Type: model.VariableTypeCertificate,
			Options: model.VariableOptions{
				"is_ca":             true,
				"alternative_names": []string{"subject names"},
			},
			CVOptions: model.CVOptions{Secret: true},
		}
		err := RecordCertInfo(certInfo, configVar)

		assert.EqualError(t, err, "CA Cert for SSL id `CERT_NAME` should not have subject names")
	})

	t.Run("Role name not allowed on CA certs", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name: "CERT_NAME",
			Type: model.VariableTypeCertificate,
			Options: model.VariableOptions{
				"is_ca": true,
			},
			CVOptions: model.CVOptions{
				Secret:   true,
				RoleName: "role name",
			},
		}
		err := RecordCertInfo(certInfo, configVar)

		assert.EqualError(t, err, "CA Cert for SSL id `CERT_NAME` should not have a role name")
	})

	t.Run("append_kube_ca sets path to kube CA cert", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.VariableDefinition{
			Name: certID,
			Type: model.VariableTypeCertificate,
			Options: model.VariableOptions{
				"is_ca":          true,
				"append_kube_ca": true,
			},
			CVOptions: model.CVOptions{
				Secret: true,
			},
		}
		err := RecordCertInfo(certInfo, configVar)

		require.NoError(t, err)
		assert.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", certInfo[certID].KubeCACertFile)
	})

}

func TestGenerateCerts(t *testing.T) {
	t.Parallel()

	t.Run("Check createCA is called properly", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = CertInfo{
			IsAuthority:     true,
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			// SubjectNames & RoleName should not be used for CA certs; they are only included
			// here as bait, in case GenerateCerts() decides to call createCert instead of createCA
			SubjectNames: []string{"subject-names"},
			RoleName:     "dummy-role",
			CAName:       defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := GenerateCerts(certInfo, nil, "namespace", "cluster.domain", 700, false, secrets)

		assert.NoError(t, err)
		assert.NotEmpty(t, secrets.Data[certInfo[defaultCA].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[defaultCA].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[defaultCA].CertificateName])
		require.NotNil(t, certBlob, "Failed to decode certificate PEM block")

		cert, err := x509.ParseCertificate(certBlob.Bytes)
		require.NoError(t, err)

		assert.True(t, cert.IsCA, "CA cert is a CA cert")
		assert.True(t, cert.NotAfter.After(time.Now().Add(698*24*time.Hour)))
		assert.True(t, cert.NotAfter.Before(time.Now().Add(702*24*time.Hour)))
		assert.Empty(t, cert.DNSNames, "CA cert should not include any DNS names")
	})

	t.Run("Check createCert is called properly", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			IsAuthority:     false,
			PrivateKeyName:  "ca-key",
			CertificateName: "ca-name",
			CAName:          defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := GenerateCerts(certInfo, nil, "namespace", "cluster.domain", 365, false, secrets)

		assert.EqualError(t, err, "CA "+defaultCA+" not found")
		assert.Empty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.Empty(t, secrets.Data[certInfo[certID].CertificateName])

		certInfo[defaultCA] = CertInfo{
			IsAuthority:     true,
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			RoleName:        "dummy-role",
			CAName:          defaultCA,
		}
		err = GenerateCerts(certInfo, nil, "namespace", "cluster.domain", 30, false, secrets)

		assert.NoError(t, err)
		assert.NotEmpty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[certID].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[certID].CertificateName])
		require.NotNil(t, certBlob, "Failed to decode certificate PEM block")

		cert, err := x509.ParseCertificate(certBlob.Bytes)
		require.NoError(t, err)

		assert.False(t, cert.IsCA, "cert is NOT a CA cert")
		assert.True(t, cert.NotAfter.After(time.Now().Add(28*24*time.Hour)))
		assert.True(t, cert.NotAfter.Before(time.Now().Add(32*24*time.Hour)))
		assert.NotEmpty(t, cert.DNSNames, "Normal cert should include some DNS names")
	})

	t.Run("If secrets already has a private key, do nothing", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")

		certInfo := make(map[string]CertInfo)
		createCA(certInfo, secrets, defaultCA, 365)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			CAName:          defaultCA,
		}

		err := GenerateCerts(certInfo, nil, "namespace", "cluster.domain", 365, false, secrets)

		assert.NoError(t, err)
		assert.Equal(t, []byte("private-key-data"), secrets.Data["private-key"])
		assert.Equal(t, []byte("certificate-data"), secrets.Data["certificate-name"])
	})

	t.Run("secrets.Data should have a private key and a certificate", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		secrets := &v1.Secret{Data: map[string][]byte{}}
		createCA(certInfo, secrets, defaultCA, 365)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          defaultCA,
		}

		err := GenerateCerts(certInfo, nil, "namespace", "cluster.domain", 365, false, secrets)
		require.NoError(t, err, "Error creating certificate")

		assert.NotEmpty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[certID].CertificateName])
		_, err = tls.X509KeyPair(secrets.Data[certInfo[certID].CertificateName], secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NoError(t, err)
	})

}

func TestRsaKeyRequest(t *testing.T) {
	t.Parallel()

	kr := rsaKeyRequest()
	assert.Equal(t, 4096, kr.S)
}

func TestCreateCA(t *testing.T) {
	t.Parallel()

	t.Run("createCA shouldn't update if PrivateKeyName is defined", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")

		createCA(certInfo, secrets, certID, 365)

		assert.Equal(t, []byte("private-key-data"), certInfo[certID].PrivateKey)
		assert.Equal(t, []byte("certificate-data"), certInfo[certID].Certificate)
	})

	t.Run("createCA should generate valid data", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		createCA(certInfo, secrets, certID, 365)

		assert.NotEqual(t, secrets.Data[certInfo[certID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[certID].CertificateName], []byte{})
		assert.Regexp(t, `(?s)\A-----BEGIN CERTIFICATE-----\n.*\n-----END CERTIFICATE-----\n\z`,
			string(secrets.Data[certInfo[certID].CertificateName]))
	})

	t.Run("createCA appends kube CA cert when requested", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			KubeCACertFile:  "testdata/kubeca.crt",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		createCA(certInfo, secrets, certID, 365)

		assert.NotEqual(t, secrets.Data[certInfo[certID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[certID].CertificateName], []byte{})
		assert.Contains(t, string(secrets.Data[certInfo[certID].CertificateName]),
			"-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nThisIsJustTestData")
	})
}

func TestAddHost(t *testing.T) {
	t.Parallel()

	t.Run("Only host is added when wildcard is false", func(t *testing.T) {
		t.Parallel()

		req := &csr.CertificateRequest{}
		addHost(req, false, "name")

		assert.Equal(t, "name", req.Hosts[0])
		assert.Len(t, req.Hosts, 1)
	})

	t.Run("Wildcard entry is added when wildcard is false", func(t *testing.T) {
		t.Parallel()

		req := &csr.CertificateRequest{}
		addHost(req, true, "name")

		assert.Equal(t, "name", req.Hosts[0])
		assert.Equal(t, "*.name", req.Hosts[1])
		assert.Len(t, req.Hosts, 2)
	})
}

func TestCreateCert(t *testing.T) {
	t.Parallel()

	// Initialize a default CA for later use
	defaultCertInfo := make(map[string]CertInfo)
	secrets := &v1.Secret{Data: map[string][]byte{}}
	createCA(defaultCertInfo, secrets, defaultCA, 365)

	t.Run("If the default CA private key isn't found, return an error", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = CertInfo{
			Certificate: defaultCertInfo[defaultCA].Certificate,
		}
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		newCert, err := createCert(certInfo, nil, "namespace", "cluster.domain", secrets, certID, 365, false)

		assert.EqualError(t, err, "CA "+defaultCA+" not found")
		assert.Nil(t, newCert, "New cert generated even with error")
	})

	t.Run("If the default CA certificate isn't found, return an error", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = CertInfo{
			PrivateKey: defaultCertInfo[defaultCA].PrivateKey,
		}
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		newCert, err := createCert(certInfo, nil, "namespace", "cluster.domain", secrets, certID, 365, false)

		assert.EqualError(t, err, "CA "+defaultCA+" not found")
		assert.Nil(t, newCert, "New cert generated even with error")
	})

	t.Run("If CA cert fails to parse, it should return an error", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		// Create a bogus default CA
		certInfo[defaultCA] = CertInfo{
			Certificate: []byte("default-certificate"),
			PrivateKey:  []byte("private-key"),
		}
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		newCert, err := createCert(certInfo, nil, "namespace", "cluster.domain", secrets, certID, 365, false)
		require.Error(t, err, "Expected CA parsing to fail")

		assert.Contains(t, err.Error(), "Cannot parse CA cert")
		assert.Nil(t, newCert, "New cert generated even with error")
	})

	t.Run("If CA private key fails to parse, it should return an error", func(t *testing.T) {
		t.Parallel()

		// Invalidate the private key of the default CA
		info := defaultCertInfo[defaultCA]
		info.PrivateKey = []byte("private-key")

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = info
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		newCert, err := createCert(certInfo, nil, "namespace", "cluster.domain", secrets, certID, 365, false)
		require.Error(t, err, "Expected CA parsing to fail")

		assert.Contains(t, err.Error(), "Cannot parse CA private key")
		assert.Nil(t, newCert, "New cert generated even with error")
	})

	t.Run("rolename isn't empty and the env is valid", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = defaultCertInfo[defaultCA]
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames: []string{
				"*.star",
				"foo.bar",
			},
			RoleName: "dummy-role",
			CAName:   defaultCA,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		newCert, err := createCert(certInfo, nil, "namespace", "cluster.domain", secrets, certID, 365, false)
		require.NoError(t, err)

		assert.NotEmpty(t, newCert.PrivateKey)
		assert.NotEmpty(t, newCert.Certificate)
		assert.Empty(t, newCert.CSRName)

		certBlob, _ := pem.Decode(newCert.Certificate)
		require.NotNil(t, certBlob, "Failed to decode certificate PEM block")

		cert, err := x509.ParseCertificate(certBlob.Bytes)
		require.NoError(t, err)

		assert.Contains(t, cert.DNSNames, "dummy-role")
		assert.Contains(t, cert.DNSNames, "*.dummy-role")
		assert.Contains(t, cert.DNSNames, "dummy-role.namespace.svc")
		assert.Contains(t, cert.DNSNames, "*.dummy-role.namespace.svc")
		assert.Contains(t, cert.DNSNames, "dummy-role.namespace.svc.cluster.domain")
		assert.Contains(t, cert.DNSNames, "*.dummy-role.namespace.svc.cluster.domain")

		assert.Contains(t, cert.DNSNames, "*.dummy-role-set")
		assert.Contains(t, cert.DNSNames, "*.dummy-role-set.namespace.svc")
		assert.Contains(t, cert.DNSNames, "*.dummy-role-set.namespace.svc.cluster.domain")

		assert.Contains(t, cert.DNSNames, "*.star")
		assert.Contains(t, cert.DNSNames, "foo.bar")

		assert.NotContains(t, cert.DNSNames, "dummy-role-set")
		assert.NotContains(t, cert.DNSNames, "dummy-role-set.namespace.svc")
		assert.NotContains(t, cert.DNSNames, "dummy-role-set.namespace.svc.cluster.domain")
		assert.NotContains(t, cert.DNSNames, "*.*.dummy-role-set")
		assert.NotContains(t, cert.DNSNames, "*.*.dummy-role-set.namespace.svc")
		assert.NotContains(t, cert.DNSNames, "*.*.dummy-role-set.namespace.svc.cluster.domain")
	})

	t.Run("Create a kube csr, without auto-approval", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          "",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}
		csrName := "namespace-" + certID

		var csri MockCertificateSigningRequestInterface
		csri.On("Delete", csrName, &metav1.DeleteOptions{})
		csri.On("Create", mock.AnythingOfType("*v1beta1.CertificateSigningRequest"))

		newCert, err := createCert(certInfo, &csri, "namespace", "cluster.domain", secrets, certID, 365, false)
		csri.AssertCalled(t, "Delete", csrName, &metav1.DeleteOptions{})
		csri.AssertCalled(t, "Create", mock.Anything)

		require.NoError(t, err)
		assert.Equal(t, newCert.CSRName, csrName)
	})

	t.Run("Create a kube csr, with auto-approval", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			CAName:          "",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}
		csrName := "namespace-" + certID

		var csri MockCertificateSigningRequestInterface
		csri.On("Delete", csrName, &metav1.DeleteOptions{})
		csri.On("Create", mock.AnythingOfType("*v1beta1.CertificateSigningRequest"))
		csri.On("Get", csrName, metav1.GetOptions{})
		csri.On("UpdateApproval", mock.AnythingOfType("*v1beta1.CertificateSigningRequest"))

		newCert, err := createCert(certInfo, &csri, "namespace", "cluster.domain", secrets, certID, 365, true)
		csri.AssertCalled(t, "Delete", csrName, &metav1.DeleteOptions{})
		csri.AssertCalled(t, "Create", mock.Anything)
		csri.AssertCalled(t, "Get", csrName, metav1.GetOptions{})
		csri.AssertCalled(t, "UpdateApproval", mock.Anything)

		require.NoError(t, err)
		assert.Equal(t, newCert.CSRName, csrName)
	})
}

func TestCreateKubeCSR(t *testing.T) {
	t.Parallel()

	t.Run("createKubeCSR creates a new CSR and sets a normalized name", func(t *testing.T) {
		t.Parallel()

		var csri MockCertificateSigningRequestInterface
		info := CertInfo{CAName: ""}
		request := []byte("my-request")
		csrName := "namespace-foo-bar"

		csri.On("Delete", csrName, &metav1.DeleteOptions{})
		csri.On("Create", mock.AnythingOfType("*v1beta1.CertificateSigningRequest"))

		newCert, err := createKubeCSR(&csri, request, info, "namespace", "FOO_BAR", false)

		csri.AssertCalled(t, "Delete", csrName, &metav1.DeleteOptions{})
		csri.AssertCalled(t, "Create", mock.Anything)

		require.NoError(t, err)
		assert.Equal(t, newCert.CSRName, csrName)
	})
}

func TestApproveKubeCSR(t *testing.T) {
	t.Parallel()

	t.Run("approveKubeCSR fetches the CSR and approves it", func(t *testing.T) {
		t.Parallel()

		var csri MockCertificateSigningRequestInterface
		csri.On("Get", "foo", metav1.GetOptions{})
		csri.On("UpdateApproval", mock.AnythingOfType("*v1beta1.CertificateSigningRequest"))

		approveKubeCSR(&csri, "foo")

		csri.AssertCalled(t, "Get", "foo", metav1.GetOptions{})
		csri.AssertCalled(t, "UpdateApproval", mock.Anything)
	})
}

func TestWaitForKubeCSR(t *testing.T) {
	t.Parallel()

	t.Run("waitForKubeCSR repeatedly fetches the CSR until it is approved", func(t *testing.T) {
		t.Parallel()

		var csri MockCertificateSigningRequestInterface
		info := CertInfo{CSRName: string(certificates.CertificateApproved)}

		csri.On("Get", info.CSRName, metav1.GetOptions{})

		newCert, err := waitForKubeCSR(&csri, info)

		csri.AssertCalled(t, "Get", info.CSRName, metav1.GetOptions{})

		require.NoError(t, err)
		assert.Equal(t, newCert.Certificate, []byte("shiny"))
	})

	t.Run("waitForKubeCSR repeatedly fetches the CSR until it is denied", func(t *testing.T) {
		t.Parallel()

		var csri MockCertificateSigningRequestInterface
		info := CertInfo{CSRName: string(certificates.CertificateDenied)}

		csri.On("Get", info.CSRName, metav1.GetOptions{})

		_, err := waitForKubeCSR(&csri, info)

		csri.AssertCalled(t, "Get", info.CSRName, metav1.GetOptions{})

		assert.EqualError(t, err, "kube csr Denied denied, reason: because, why not?, message: Seriously!")
	})

	t.Run("waitForKubeCSR returns an error if the CSR cannot be found", func(t *testing.T) {
		t.Parallel()

		var csri MockCertificateSigningRequestInterface
		info := CertInfo{CSRName: "Failed"}

		csri.On("Get", info.CSRName, metav1.GetOptions{})

		_, err := waitForKubeCSR(&csri, info)

		csri.AssertCalled(t, "Get", info.CSRName, metav1.GetOptions{})

		assert.EqualError(t, err, "fetching kube csr Failed returned error Something went wrong")
	})
}
