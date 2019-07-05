package ssl

import (
	"fmt"
	glog "log"
	"time"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"

	v1 "k8s.io/api/core/v1"
)

const defaultCA = "cacert"

// CertInfo contains all the information required to generate an SSL cert
type CertInfo struct {
	PrivateKeyName  string // Name to associate with private key
	CertificateName string // Name to associate with certificate
	IsAuthority     bool
	CAName          string

	SubjectNames []string
	RoleName     string

	Certificate []byte
	PrivateKey  []byte
}

// RecordCertInfo record cert information for later generation
func RecordCertInfo(certInfo map[string]CertInfo, configVar *model.VariableDefinition) error {
	params, err := configVar.OptionsAsCertificateParams()
	if err != nil {
		return fmt.Errorf("Config variable `%s` has invalid certificate options", configVar.Name)
	}

	// We will use the configVar.Name of CAs as reference in certs though
	// variable names are unique, so we get a fresh CertInfo{}
	info := certInfo[configVar.Name]

	// Previously key and ID had the same Generator.ID, now they're not separate entries
	info.CertificateName = util.ConvertNameToKey(configVar.Name)
	info.PrivateKeyName = util.ConvertNameToKey(configVar.Name + model.KeySuffix)

	info.IsAuthority = params.IsCA

	if len(params.CAName) > 0 {
		if params.IsCA {
			return fmt.Errorf("CA for SSL id `%s` should not have a CA", configVar.Name)
		}
		info.CAName = params.CAName
	}

	if len(params.AlternativeNames) > 0 {
		if params.IsCA {
			return fmt.Errorf("CA Cert for SSL id `%s` should not have subject names", configVar.Name)
		}
		info.SubjectNames = params.AlternativeNames
	}

	if configVar.CVOptions.RoleName != "" {
		if params.IsCA {
			return fmt.Errorf("CA Cert for SSL id `%s` should not have a role name", configVar.Name)
		}
		info.RoleName = configVar.CVOptions.RoleName
	}

	certInfo[configVar.Name] = info
	return nil
}

// GenerateCerts creates an SSL cert and private key
func GenerateCerts(certInfo map[string]CertInfo, namespace, clusterDomain string, expiration int, secrets *v1.Secret) error {
	// generate all the CAs first because they are needed to sign the certs
	for id, info := range certInfo {
		if !info.IsAuthority {
			continue
		}
		glog.Printf("- SSL CA: %s\n", id)
		err := createCA(certInfo, secrets, id, expiration)
		if err != nil {
			return err
		}
	}
	for id, info := range certInfo {
		if info.IsAuthority {
			continue
		}
		glog.Printf("- SSL CRT: %s (%s / %s)\n", id, info.CertificateName, info.PrivateKeyName)
		if len(info.SubjectNames) == 0 && info.RoleName == "" {
			glog.Printf("Warning: certificate %s has no names\n", info.CertificateName)
		}
		err := createCert(certInfo, namespace, clusterDomain, secrets, id, expiration)
		if err != nil {
			return err
		}
	}
	return nil
}

func rsaKeyRequest() *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{A: "rsa", S: 4096}
}

func createCA(certInfo map[string]CertInfo, secrets *v1.Secret, id string, expiration int) error {
	var err error
	info := certInfo[id]

	if len(secrets.Data[info.PrivateKeyName]) > 0 && len(secrets.Data[info.CertificateName]) > 0 {
		// fetch CA from secrets because we may need it to sign new certs
		info.PrivateKey = secrets.Data[info.PrivateKeyName]
		info.Certificate = secrets.Data[info.CertificateName]
		certInfo[id] = info
		return nil
	}

	req := &csr.CertificateRequest{
		CA:         &csr.CAConfig{Expiry: fmt.Sprintf("%dh", expiration*24)},
		CN:         "SCF CA",
		KeyRequest: rsaKeyRequest(),
	}
	info.Certificate, _, info.PrivateKey, err = initca.New(req)
	if err != nil {
		return fmt.Errorf("Cannot create CA: %s", err)
	}

	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate

	certInfo[id] = info
	return nil
}

func addHost(req *csr.CertificateRequest, wildcard bool, name string) {
	req.Hosts = append(req.Hosts, name)
	if wildcard {
		req.Hosts = append(req.Hosts, "*."+name)
	}
}

func createCert(certInfo map[string]CertInfo, namespace, clusterDomain string, secrets *v1.Secret, id string, expiration int) error {
	var err error
	info := certInfo[id]

	// Just one of the fields may be deleted by changes to the generator input.
	// Need to generate a new cert if either is missing.
	if len(secrets.Data[info.PrivateKeyName]) > 0 && len(secrets.Data[info.CertificateName]) > 0 {
		return nil
	}

	caName := defaultCA
	if info.CAName != "" {
		caName = info.CAName
	}

	caInfo := certInfo[caName]
	if len(caInfo.PrivateKey) == 0 || len(caInfo.Certificate) == 0 {
		return fmt.Errorf("CA %s not found", caName)
	}

	req := &csr.CertificateRequest{KeyRequest: rsaKeyRequest()}

	if info.RoleName != "" {
		addHost(req, true, info.RoleName)
		addHost(req, true, fmt.Sprintf("%s.%s.svc", info.RoleName, namespace))
		addHost(req, true, fmt.Sprintf("%s.%s.svc.%s", info.RoleName, namespace, clusterDomain))

		// Generate wildcard certs for stateful sets for self-clustering roles
		// We do this instead of having a bunch of subject alt names so that the
		// certs can work correctly if we scale the cluster post-deployment.
		prefix := fmt.Sprintf("*.%s-set", info.RoleName)
		addHost(req, false, prefix)
		addHost(req, false, fmt.Sprintf("%s.%s.svc", prefix, namespace))
		addHost(req, false, fmt.Sprintf("%s.%s.svc.%s", prefix, namespace, clusterDomain))
	}

	for _, name := range info.SubjectNames {
		addHost(req, false, name)
	}

	if len(req.Hosts) == 0 {
		req.Hosts = append(req.Hosts, info.CertificateName)
	}
	req.CN = req.Hosts[0]

	var signingReq []byte
	g := &csr.Generator{Validator: genkey.Validator}
	signingReq, info.PrivateKey, err = g.ProcessRequest(req)
	if err != nil {
		return fmt.Errorf("Cannot generate cert: %s", err)
	}

	caCert, err := helpers.ParseCertificatePEM(caInfo.Certificate)
	if err != nil {
		return fmt.Errorf("Cannot parse CA cert: %s", err)
	}
	caKey, err := helpers.ParsePrivateKeyPEM(caInfo.PrivateKey)
	if err != nil {
		return fmt.Errorf("Cannot parse CA private key: %s", err)
	}

	signingProfile := &config.SigningProfile{
		Usage:        []string{"server auth", "client auth"},
		Expiry:       time.Duration(expiration*24) * time.Hour,
		ExpiryString: fmt.Sprintf("%dh", expiration*24),
	}
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  signingProfile,
	}

	s, err := local.NewSigner(caKey, caCert, signer.DefaultSigAlgo(caKey), policy)
	if err != nil {
		return fmt.Errorf("Cannot create signer: %s", err)
	}

	info.Certificate, err = s.Sign(signer.SignRequest{Request: string(signingReq)})
	if err != nil {
		return fmt.Errorf("Failed to sign cert: %s", err)
	}

	if len(info.PrivateKeyName) == 0 {
		return fmt.Errorf("Certificate %s created with empty private key name", id)
	}
	if len(info.PrivateKey) == 0 {
		return fmt.Errorf("Certificate %s created with empty private key", id)
	}
	if len(info.CertificateName) == 0 {
		return fmt.Errorf("Certificate %s created with empty certificate name", id)
	}
	if len(info.Certificate) == 0 {
		return fmt.Errorf("Certificate %s created with empty certificate", id)
	}
	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate
	certInfo[id] = info

	return nil
}
