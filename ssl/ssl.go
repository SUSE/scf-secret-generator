package ssl

import (
	"fmt"
	"io/ioutil"
	glog "log"
	"sync"
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

	certificates "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertInfo contains all the information required to generate an SSL cert
type CertInfo struct {
	PrivateKeyName  string // Name to associate with private key
	CertificateName string // Name to associate with certificate
	IsAuthority     bool
	KubeCACertFile  string
	CAName          string

	SubjectNames []string
	RoleName     string

	Certificate []byte
	PrivateKey  []byte

	CSRName string // Name of kube csr
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

	if params.AppendKubeCA && !params.IsCA {
		return fmt.Errorf("Can't append kube CA to regular cert id `%s`; only works for CA certs",
			configVar.Name)
	}

	info.IsAuthority = params.IsCA
	if params.AppendKubeCA {
		info.KubeCACertFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	}

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
func GenerateCerts(certInfo map[string]CertInfo, csri util.CertificateSigningRequestInterface, namespace, clusterDomain string, expiration int, autoApproval bool, secrets *v1.Secret) error {
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

	wg := sync.WaitGroup{}
	mut := sync.Mutex{}
	errs := []error{}
	newCerts := map[string]*CertInfo{}

	for id, info := range certInfo {
		if info.IsAuthority {
			continue
		}
		glog.Printf("- SSL CRT: %s (%s / %s)\n", id, info.CertificateName, info.PrivateKeyName)
		if len(info.SubjectNames) == 0 && info.RoleName == "" {
			glog.Printf("Warning: certificate %s has no names\n", info.CertificateName)
		}

		wg.Add(1)
		go func(id string, info CertInfo) {
			defer wg.Done()
			// Just one of the fields may be deleted by changes to the generator input.
			// Need to generate a new cert if either is missing.
			mut.Lock()
			if len(secrets.Data[info.PrivateKeyName]) > 0 && len(secrets.Data[info.CertificateName]) > 0 {
				mut.Unlock()
				return
			}
			mut.Unlock()

			newCert, err := createCert(certInfo, csri, namespace, clusterDomain, secrets, id, expiration, autoApproval)
			mut.Lock()
			defer mut.Unlock()
			if err != nil {
				errs = append(errs, err)
			} else {
				if newCert == nil {
					panic("createCert returned no errors, but no certificate either")
				}
				secrets.Data[newCert.PrivateKeyName] = newCert.PrivateKey
				secrets.Data[newCert.CertificateName] = newCert.Certificate
				// We stash the new certificate in a secondary map so that we
				// can freely read `certInfo` in `createCert()`` (to look up the
				// CA needed to generate other certificates) without triggering
				// data races.
				newCerts[id] = newCert
			}
		}(id, info)
	}
	wg.Wait()

	var err error
	if len(errs) > 0 {
		err = errs[0]
	}

	for id, newCert := range newCerts {
		if newCert.CSRName != "" {
			if err == nil {
				newCert, err = waitForKubeCSR(csri, *newCert)
				if err != nil {
					err = fmt.Errorf("Kube CSR failed with %s", err)
				}
				secrets.Data[newCert.PrivateKeyName] = newCert.PrivateKey
				secrets.Data[newCert.CertificateName] = newCert.Certificate
			}
			_ = csri.Delete(newCert.CSRName, &metav1.DeleteOptions{})
		}

		// Once we hit an error we just delete all still outstanding kube csrs
		// and then return the first error we encountered.
		if err != nil {
			continue
		}

		if len(newCert.PrivateKeyName) == 0 {
			err = fmt.Errorf("Certificate %s created with empty private key name", id)
		} else if len(newCert.PrivateKey) == 0 {
			err = fmt.Errorf("Certificate %s created with empty private key", id)
		} else if len(newCert.CertificateName) == 0 {
			err = fmt.Errorf("Certificate %s created with empty certificate name", id)
		} else if len(newCert.Certificate) == 0 {
			err = fmt.Errorf("Certificate %s created with empty certificate", id)
		}
		certInfo[id] = *newCert
	}
	return err
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

	if info.KubeCACertFile != "" {
		glog.Printf("appending kube CA cert from %s to to CA cert %s", info.KubeCACertFile, id)

		kubeCert, err := ioutil.ReadFile(info.KubeCACertFile)
		if err != nil {
			return fmt.Errorf("Cannot read kube CA cert: %s", err)
		}
		secrets.Data[info.CertificateName] = append(secrets.Data[info.CertificateName], kubeCert...)
	}

	certInfo[id] = info

	return nil
}

func addHost(req *csr.CertificateRequest, wildcard bool, name string) {
	req.Hosts = append(req.Hosts, name)
	if wildcard {
		req.Hosts = append(req.Hosts, "*."+name)
	}
}

// createCert generates a new certificate (for the given id).  Note that this
// returns the new certificate, rather than modifying it in-place, in order to
// make it possible for various certificates to be generated in parallel.  This
// is useful as key generation can be slow.
func createCert(certInfo map[string]CertInfo, csri util.CertificateSigningRequestInterface, namespace, clusterDomain string, secrets *v1.Secret, id string, expiration int, autoApproval bool) (*CertInfo, error) {
	var err error
	info := certInfo[id]

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
		return nil, fmt.Errorf("Cannot generate csr: %s", err)
	}

	if info.CAName == "" {
		info, err := createKubeCSR(csri, signingReq, info, namespace, id, autoApproval)
		if err == nil && autoApproval {
			approveKubeCSR(csri, info.CSRName)
		}
		return info, err
	}

	caInfo := certInfo[info.CAName]
	if len(caInfo.PrivateKey) == 0 || len(caInfo.Certificate) == 0 {
		return nil, fmt.Errorf("CA %s not found", info.CAName)
	}

	caCert, err := helpers.ParseCertificatePEM(caInfo.Certificate)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse CA cert: %s", err)
	}
	caKey, err := helpers.ParsePrivateKeyPEM(caInfo.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse CA private key: %s", err)
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
		return nil, fmt.Errorf("Cannot create signer: %s", err)
	}

	info.Certificate, err = s.Sign(signer.SignRequest{Request: string(signingReq)})
	if err != nil {
		return nil, fmt.Errorf("Failed to sign cert: %s", err)
	}

	return &info, nil
}
func createKubeCSR(csri util.CertificateSigningRequestInterface, request []byte, info CertInfo, namespace, id string, autoApproval bool) (*CertInfo, error) {
	csr := &certificates.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: util.ConvertNameToKey(fmt.Sprintf("%s-%s", namespace, id)),
		},
		Spec: certificates.CertificateSigningRequestSpec{
			Request: request,
			Usages: []certificates.KeyUsage{
				certificates.UsageClientAuth,
				certificates.UsageServerAuth,
			},
			// expiration is determined by apiserver and cannot be configured
		},
	}
	glog.Printf("create kube csr %s", csr.Name)
	err := csri.Delete(csr.Name, &metav1.DeleteOptions{})
	if err == nil {
		glog.Printf("kube csr %s already existed and has been deleted", csr.Name)
	}
	csr, err = csri.Create(csr)
	if err == nil {
		info.CSRName = csr.Name
	}
	return &info, err
}

func approveKubeCSR(csri util.CertificateSigningRequestInterface, csrName string) {
	glog.Printf("attempting to auto-approve kube csr %s", csrName)

	csr, err := csri.Get(csrName, metav1.GetOptions{})
	if err != nil {
		glog.Printf("unexpected error during get kube csr %s: %v", csrName, err)
		return
	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificates.CertificateSigningRequestCondition{
		Type:    certificates.CertificateApproved,
		Reason:  "Autoapproved",
		Message: "This csr was approved automatically by scf-secrets-generator",
	})
	csr, err = csri.UpdateApproval(csr)
	if err != nil {
		glog.Printf("cannot auto-approve kube csr %s: %v\nwaiting for manual approval", csr.Name, err)
	} else {
		glog.Printf("kube csr %s has been auto-approved", csr.Name)
	}
}

func waitForKubeCSR(csri util.CertificateSigningRequestInterface, info CertInfo) (*CertInfo, error) {
	name := info.CSRName
	var csr *certificates.CertificateSigningRequest
	var err error

	for retry := 0; ; retry++ {
		csr, err = csri.Get(name, metav1.GetOptions{})
		if err != nil {
			return &info, fmt.Errorf("fetching kube csr %s returned error %s", name, err)
		}
		for _, condition := range csr.Status.Conditions {
			switch condition.Type {
			case certificates.CertificateApproved:
				info.Certificate = csr.Status.Certificate
				return &info, nil
			case certificates.CertificateDenied:
				return &info, fmt.Errorf("kube csr %s denied, reason: %s, message: %s",
					name, condition.Reason, condition.Message)
			}
		}
		switch {
		case retry == 0:
			glog.Printf("waiting for kube csr %s to be approved", name)
			time.Sleep(2 * time.Second)
		case retry < 10:
			time.Sleep(5 * time.Second)
		default:
			time.Sleep(20 * time.Second)
		}
	}
}
