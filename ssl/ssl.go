package ssl

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
var updateCert = updateCertImpl
var getEnv = os.Getenv

const DEFAULT_CA = "cacert"

type CertInfo struct {
	PrivateKeyName  string // Name to associate with private key
	CertificateName string // Name to associate with certificate

	SubjectNames []string
	RoleName     string

	Certificate []byte
	PrivateKey  []byte
}

var certInfo = make(map[string]CertInfo)

func RecordCertInfo(configVar *model.ConfigurationVariable) {
	info := certInfo[configVar.Generator.ID]

	if configVar.Generator.ValueType == model.ValueTypeCertificate {
		info.CertificateName = util.ConvertNameToKey(configVar.Name)
	} else if configVar.Generator.ValueType == model.ValueTypePrivateKey {
		info.PrivateKeyName = util.ConvertNameToKey(configVar.Name)
	}

	if len(configVar.Generator.SubjectNames) > 0 {
		info.SubjectNames = configVar.Generator.SubjectNames
	}
	if configVar.Generator.RoleName != "" {
		info.RoleName = configVar.Generator.RoleName
	}
	certInfo[configVar.Generator.ID] = info
}

func GenerateCerts(secrets *v1.Secret, updates *v1.Secret) (dirty bool) {
	// generate all the CAs first because they are needed to sign the certs
	for id, info := range certInfo {
		if len(info.SubjectNames) == 0 && info.RoleName == "" {
			dirty = createCA(secrets, updates, id) || dirty
		}
	}
	for id, info := range certInfo {
		if len(info.SubjectNames) > 0 || info.RoleName != "" {
			dirty = createCert(secrets, updates, id) || dirty
		}
	}
	return
}

func rsaKeyRequest() *csr.BasicKeyRequest {
	return &csr.BasicKeyRequest{A: "rsa", S: 4096}
}

func createCAImpl(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	var err error
	info := certInfo[id]

	if len(secrets.Data[info.PrivateKeyName]) > 0 {
		// fetch CA from secrets because we may need it to sign new certs
		info.PrivateKey = secrets.Data[info.PrivateKeyName]
		info.Certificate = secrets.Data[info.CertificateName]
		certInfo[id] = info
		return false
	}
	if updateCert(secrets, updates, id) {
		return true
	}

	req := csr.CertificateRequest{
		CA:         &csr.CAConfig{Expiry: "262800h"}, // 30 years
		CN:         "SCF CA",
		KeyRequest: rsaKeyRequest(),
	}
	info.Certificate, _, info.PrivateKey, err = initca.New(&req)
	if err != nil {
		logFatalf("Cannot create CA: %s", err)
		return false
	}

	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate
	certInfo[id] = info
	return true
}

func addHost(req *csr.CertificateRequest, wildcard bool, name string) {
	name = util.ExpandEnvTemplates(name)
	req.Hosts = append(req.Hosts, name)
	if wildcard {
		req.Hosts = append(req.Hosts, "*."+name)
	}
}

func createCertImpl(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	var err error
	info := certInfo[id]

	if len(secrets.Data[info.PrivateKeyName]) > 0 {
		return false
	}
	if updateCert(secrets, updates, id) {
		return true
	}

	// XXX Add support for multiple CAs
	caInfo := certInfo[DEFAULT_CA]
	if len(caInfo.PrivateKey) == 0 || len(caInfo.Certificate) == 0 {
		logFatalf("CA %s not found", DEFAULT_CA)
		return false
	}

	req := csr.CertificateRequest{KeyRequest: rsaKeyRequest()}

	if info.RoleName != "" {
		// get role instance count from environment
		envName := fmt.Sprintf("KUBE_SIZING_%s_COUNT", strings.Replace(strings.ToUpper(info.RoleName), "-", "_", -1))
		envVal := getEnv(envName)
		count, err := strconv.ParseInt(envVal, 10, 0)
		if err != nil {
			logFatalf("Cannot parse %s value '%s': %s", envName, envVal, err)
			return false
		}

		addHost(&req, true, info.RoleName)
		addHost(&req, true, info.RoleName+".{{.KUBERNETES_NAMESPACE}}.svc")
		addHost(&req, true, info.RoleName+".{{.KUBERNETES_NAMESPACE}}.svc.cluster.local")

		for i := 0; i < int(count); i++ {
			subdomain := fmt.Sprintf("%s-%d.%s-set", info.RoleName, i, info.RoleName)
			addHost(&req, false, subdomain)
			addHost(&req, false, subdomain+".{{.KUBERNETES_NAMESPACE}}.svc")
			addHost(&req, false, subdomain+".{{.KUBERNETES_NAMESPACE}}.svc.cluster.local")
		}
		addHost(&req, true, info.RoleName+".{{.KUBE_SERVICE_DOMAIN_SUFFIX}}")
	}

	for _, name := range info.SubjectNames {
		addHost(&req, false, name)
	}

	req.CN = req.Hosts[0]

	var signingReq []byte
	g := &csr.Generator{Validator: genkey.Validator}
	signingReq, info.PrivateKey, err = g.ProcessRequest(&req)
	if err != nil {
		logFatalf("Cannot generate cert: %s", err)
		return false
	}

	caCert, err := helpers.ParseCertificatePEM(caInfo.Certificate)
	if err != nil {
		logFatalf("Cannot parse CA cert: %s", err)
		return false
	}
	caKey, err := helpers.ParsePrivateKeyPEM(caInfo.PrivateKey)
	if err != nil {
		logFatalf("Cannot parse CA private key: %s", err)
		return false
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
		return false
	}

	info.Certificate, err = s.Sign(signer.SignRequest{Request: string(signingReq)})
	if err != nil {
		logFatalf("Failed to sign cert: %s", err)
		return false
	}

	secrets.Data[info.PrivateKeyName] = info.PrivateKey
	secrets.Data[info.CertificateName] = info.Certificate
	certInfo[id] = info

	return true
}

func updateCertImpl(secrets *v1.Secret, updates *v1.Secret, id string) bool {
	info := certInfo[id]

	if len(updates.Data[info.PrivateKeyName]) > 0 {
		if len(updates.Data[info.CertificateName]) == 0 {
			logFatalf("Update includes %s but not %s", info.PrivateKeyName, info.CertificateName)
			return false
		}
		secrets.Data[info.PrivateKeyName] = updates.Data[info.PrivateKeyName]
		secrets.Data[info.CertificateName] = updates.Data[info.CertificateName]

		// keep cert info in case this is a CA
		info.PrivateKey = secrets.Data[info.PrivateKeyName]
		info.Certificate = secrets.Data[info.CertificateName]
		certInfo[id] = info

		return true
	}
	if len(updates.Data[info.CertificateName]) > 0 {
		logFatalf("Update includes %s but not %s", info.CertificateName, info.PrivateKeyName)
		return false
	}
	return false
}
