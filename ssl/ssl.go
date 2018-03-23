package ssl

import (
	"fmt"
	glog "log"
	"os"
	"time"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"

	"k8s.io/api/core/v1"
)

var logFatalf = log.Fatalf
var createCA = createCAImpl
var createCert = createCertImpl
var getEnv = os.Getenv

const defaultCA = "cacert"

// CertInfo contains all the information required to generate an SSL cert
type CertInfo struct {
	PrivateKeyName  string // Name to associate with private key
	CertificateName string // Name to associate with certificate
	IsAuthority     bool

	SubjectNames []string
	RoleName     string

	Certificate []byte
	PrivateKey  []byte
}

var certInfo = make(map[string]CertInfo)

// RecordCertInfo record cert information for later generation
func RecordCertInfo(configVar *model.ConfigurationVariable) {
	info := certInfo[configVar.Generator.ID]

	switch configVar.Generator.ValueType {
	case model.ValueTypeCertificate:
		info.CertificateName = util.ConvertNameToKey(configVar.Name)
	case model.ValueTypePrivateKey:
		info.PrivateKeyName = util.ConvertNameToKey(configVar.Name)
	default:
		glog.Printf("Invalid certificate generator value_type: %s", configVar.Generator.ValueType)
	}
	info.IsAuthority = (configVar.Generator.Type == model.GeneratorTypeCACertificate)

	if len(configVar.Generator.SubjectNames) > 0 {
		info.SubjectNames = configVar.Generator.SubjectNames
	}
	if configVar.Generator.RoleName != "" {
		info.RoleName = configVar.Generator.RoleName
	}
	certInfo[configVar.Generator.ID] = info
}

// GenerateCerts creates an SSL cert and private key
func GenerateCerts(secrets *v1.Secret) {
	// generate all the CAs first because they are needed to sign the certs
	for id, info := range certInfo {
		if info.IsAuthority {
			glog.Printf("- SSL CA: %s\n", id)

			createCA(secrets, id)
		}
	}
	for id, info := range certInfo {
		if info.IsAuthority {
			continue
		}

		glog.Printf("- SSL CRT: %s (%s / %s)\n", id, info.CertificateName, info.PrivateKeyName)

		if len(info.SubjectNames) == 0 && info.RoleName == "" {
			fmt.Fprintf(os.Stderr, "Warning: certificate %s has no names\n", info.CertificateName)
		}
		createCert(secrets, id)
	}
	return
}

func rsaKeyRequest() *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{A: "rsa", S: 4096}
}

func createCAImpl(secrets *v1.Secret, id string) {
	var err error
	info := certInfo[id]

	if len(secrets.Data[info.PrivateKeyName]) > 0 {
		// fetch CA from secrets because we may need it to sign new certs
		info.PrivateKey = secrets.Data[info.PrivateKeyName]
		info.Certificate = secrets.Data[info.CertificateName]
		certInfo[id] = info
		return
	}

	req := &csr.CertificateRequest{
		CA:         &csr.CAConfig{Expiry: "262800h"}, // 30 years
		CN:         "SCF CA",
		KeyRequest: rsaKeyRequest(),
	}
	info.Certificate, _, info.PrivateKey, err = initca.New(req)
	if err != nil {
		logFatalf("Cannot create CA: %s", err)
		return
	}

	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate

	certInfo[id] = info
}

func addHost(req *csr.CertificateRequest, wildcard bool, name string) {
	name = util.ExpandEnvTemplates(name)
	req.Hosts = append(req.Hosts, name)
	if wildcard {
		req.Hosts = append(req.Hosts, "*."+name)
	}
}

func createCertImpl(secrets *v1.Secret, id string) {
	var err error
	info := certInfo[id]

	if len(secrets.Data[info.PrivateKeyName]) > 0 {
		return
	}

	// XXX Add support for multiple CAs
	caInfo := certInfo[defaultCA]
	if len(caInfo.PrivateKey) == 0 || len(caInfo.Certificate) == 0 {
		logFatalf("CA %s not found", defaultCA)
		return
	}

	req := &csr.CertificateRequest{KeyRequest: rsaKeyRequest()}

	if info.RoleName != "" {
		addHost(req, true, info.RoleName)
		addHost(req, true, info.RoleName+".{{.KUBERNETES_NAMESPACE}}.svc")
		addHost(req, true, info.RoleName+".{{.KUBERNETES_NAMESPACE}}.svc.cluster.local")

		// Generate wildcard certs for stateful sets for self-clustering roles
		// We do this instead of having a bunch of subject alt names so that the
		// certs can work correctly if we scale the cluster post-deployment.
		prefix := fmt.Sprintf("*.%s-set", info.RoleName)
		addHost(req, false, prefix)
		addHost(req, false, prefix+".{{.KUBERNETES_NAMESPACE}}.svc")
		addHost(req, false, prefix+".{{.KUBERNETES_NAMESPACE}}.svc.cluster.local")

		addHost(req, true, info.RoleName+".{{.KUBE_SERVICE_DOMAIN_SUFFIX}}")
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
		logFatalf("Cannot generate cert: %s", err)
		return
	}

	caCert, err := helpers.ParseCertificatePEM(caInfo.Certificate)
	if err != nil {
		logFatalf("Cannot parse CA cert: %s", err)
		return
	}
	caKey, err := helpers.ParsePrivateKeyPEM(caInfo.PrivateKey)
	if err != nil {
		logFatalf("Cannot parse CA private key: %s", err)
		return
	}

	signingProfile := &config.SigningProfile{
		Usage:        []string{"server auth", "client auth"},
		Expiry:       262800 * time.Hour, // 30 years
		ExpiryString: "262800h",          // 30 years
	}
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  signingProfile,
	}

	s, err := local.NewSigner(caKey, caCert, signer.DefaultSigAlgo(caKey), policy)
	if err != nil {
		logFatalf("Cannot create signer: %s", err)
		return
	}

	info.Certificate, err = s.Sign(signer.SignRequest{Request: string(signingReq)})
	if err != nil {
		logFatalf("Failed to sign cert: %s", err)
		return
	}

	if len(info.PrivateKeyName) == 0 {
		logFatalf("Certificate %s created with empty private key name", id)
	}
	if len(info.PrivateKey) == 0 {
		logFatalf("Certificate %s created with empty private key", id)
	}
	if len(info.CertificateName) == 0 {
		logFatalf("Certificate %s created with empty certificate name", id)
	}
	if len(info.Certificate) == 0 {
		logFatalf("Certificate %s created with empty certificate", id)
	}
	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate
	certInfo[id] = info
}
