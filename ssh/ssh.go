package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"log"
	"strings"

	"github.com/SUSE/scf-secret-generator/model"
)

type SSHKey struct {
	PrivateKey  string // Name to associate with private key
	Fingerprint string // Name to associate with fingerprint
}

func GenerateSSHKey(secretData map[string][]byte, key SSHKey) {
	// generate private key
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	privateBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(private),
	}

	// PEM encode private key
	secretKey := strings.Replace(strings.ToLower(key.PrivateKey), "_", "-", -1)
	secretData[secretKey] = pem.EncodeToMemory(&privateBlock)

	// generate MD5 fingerprint
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fingerprintKey := strings.Replace(strings.ToLower(key.Fingerprint), "_", "-", -1)
	secretData[fingerprintKey] = []byte(ssh.FingerprintLegacyMD5(public))
}

func ParseSSHKey(keys map[string]SSHKey, configVar *model.ConfigurationVariable) {
	var key SSHKey

	if _, ok := keys[configVar.Generator.ID]; ok {
		key = keys[configVar.Generator.ID]
	}

	if configVar.Generator.ValueType == model.ValueTypeFingerprint {
		key.Fingerprint = configVar.Name
	} else if configVar.Generator.ValueType == model.ValueTypePrivateKey {
		key.PrivateKey = configVar.Name
	}

	keys[configVar.Generator.ID] = key
}
