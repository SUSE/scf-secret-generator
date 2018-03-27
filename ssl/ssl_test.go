package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/cloudflare/cfssl/csr"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
)

const certID = "cert-id"

func TestRecordCertInfo(t *testing.T) {
	t.Parallel()
	t.Run("Certificate should be added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		assert.Equal(t, "cert-name", certInfo[certID].CertificateName)
	})

	t.Run("Private key should be added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		assert.Equal(t, "private-key-name", certInfo[certID].PrivateKeyName)
	})

	t.Run("Private key and cert should be in the same mapped value", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "CERT_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypeCertificate,
				ID:        certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		configVar = &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				ID:        certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		assert.Equal(t, "cert-name", certInfo[certID].CertificateName)
		assert.Equal(t, "private-key-name", certInfo[certID].PrivateKeyName)
	})

	t.Run("SubjectNames are added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType:    model.ValueTypePrivateKey,
				SubjectNames: []string{"subject names"},
				ID:           certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		assert.Equal(t, "subject names", certInfo[certID].SubjectNames[0])
	})

	t.Run("Rolename is added to certInfo", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)

		configVar := &model.ConfigurationVariable{
			Name:   "PRIVATE_KEY_NAME",
			Secret: true,
			Generator: &model.ConfigurationVariableGenerator{
				ValueType: model.ValueTypePrivateKey,
				RoleName:  "role name",
				ID:        certID,
			},
		}
		RecordCertInfo(certInfo, configVar)

		assert.Equal(t, "role name", certInfo[certID].RoleName)
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
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := GenerateCerts(certInfo, "namespace", "suffix", secrets)

		assert.NoError(t, err)
		assert.NotEmpty(t, secrets.Data[certInfo[defaultCA].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[defaultCA].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[defaultCA].CertificateName])
		if !assert.NotNil(t, certBlob, "Failed to decode certificate PEM block") {
			return
		}
		cert, err := x509.ParseCertificate(certBlob.Bytes)
		if assert.NoError(t, err) {
			assert.Empty(t, cert.DNSNames, "CA cert should not include any DNS names")
		}
	})

	t.Run("Check createCert is called properly", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[certID] = CertInfo{
			IsAuthority:     false,
			PrivateKeyName:  "ca-key",
			CertificateName: "ca-name",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := GenerateCerts(certInfo, "namespace", "suffix", secrets)

		if assert.Error(t, err) {
			assert.Equal(t, "CA "+defaultCA+" not found", err.Error())
		}
		assert.Empty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.Empty(t, secrets.Data[certInfo[certID].CertificateName])

		certInfo[defaultCA] = CertInfo{
			IsAuthority:     true,
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
			RoleName:        "dummy-role",
		}
		err = GenerateCerts(certInfo, "namespace", "suffix", secrets)

		assert.NoError(t, err)
		assert.NotEmpty(t, secrets.Data[certInfo[certID].PrivateKeyName])
		assert.NotEmpty(t, secrets.Data[certInfo[certID].CertificateName])

		certBlob, _ := pem.Decode(secrets.Data[certInfo[certID].CertificateName])
		if !assert.NotNil(t, certBlob, "Failed to decode certificate PEM block") {
			return
		}
		cert, err := x509.ParseCertificate(certBlob.Bytes)
		if assert.NoError(t, err) {
			assert.NotEmpty(t, cert.DNSNames, "Normal cert should include some DNS names")
		}
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

		createCA(certInfo, secrets, certID)

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

		createCA(certInfo, secrets, certID)

		assert.NotEqual(t, secrets.Data[certInfo[certID].PrivateKeyName], []byte{})
		assert.NotEqual(t, secrets.Data[certInfo[certID].CertificateName], []byte{})
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
	createCA(defaultCertInfo, secrets, defaultCA)

	t.Run("If secrets already has a private key, do nothing", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = defaultCertInfo[defaultCA]
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
		}

		secrets := &v1.Secret{Data: map[string][]byte{}}
		secrets.Data["private-key"] = []byte("private-key-data")
		secrets.Data["certificate-name"] = []byte("certificate-data")

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		assert.NoError(t, err)
		assert.Equal(t, []byte("private-key-data"), secrets.Data["private-key"])
		assert.Equal(t, []byte("certificate-data"), secrets.Data["certificate-name"])
	})

	t.Run("If the default CA private key isn't found, return an error", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = CertInfo{
			Certificate: defaultCertInfo[defaultCA].Certificate,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		if assert.Error(t, err) {
			assert.Equal(t, "CA "+defaultCA+" not found", err.Error())
		}
	})

	t.Run("If the default CA certificate isn't found, return an error", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = CertInfo{
			PrivateKey: defaultCertInfo[defaultCA].PrivateKey,
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)
		if assert.Error(t, err) {
			assert.Equal(t, "CA "+defaultCA+" not found", err.Error())
		}
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
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Cannot parse CA cert")
		}
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
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "Cannot parse CA private key")
		}
	})

	t.Run("secrets.Data should have a private key and a certificate", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = defaultCertInfo[defaultCA]
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{"subject-names"},
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		if assert.NoError(t, err) {
			assert.NotEmpty(t, secrets.Data[certInfo[certID].PrivateKeyName])
			assert.NotEmpty(t, secrets.Data[certInfo[certID].CertificateName])
			_, err := tls.X509KeyPair(secrets.Data[certInfo[certID].CertificateName],
				secrets.Data[certInfo[certID].PrivateKeyName])
			assert.NoError(t, err)
		}
	})

	t.Run("rolename isn't empty and the env is valid", func(t *testing.T) {
		t.Parallel()

		certInfo := make(map[string]CertInfo)
		certInfo[defaultCA] = defaultCertInfo[defaultCA]
		certInfo[certID] = CertInfo{
			PrivateKeyName:  "private-key",
			CertificateName: "certificate-name",
			SubjectNames:    []string{},
			RoleName:        "dummy-role",
		}
		secrets := &v1.Secret{Data: map[string][]byte{}}

		err := createCert(certInfo, "namespace", "suffix", secrets, certID)

		if !assert.NoError(t, err) {
			return
		}
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
			assert.Contains(t, cert.DNSNames, "dummy-role.suffix")
			assert.NotContains(t, cert.DNSNames, "dummy-role-set")
			assert.NotContains(t, cert.DNSNames, "*.*.dummy-role-set")
		}
	})
}
