package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"golang.org/x/crypto/ssh"
	"k8s.io/api/core/v1"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
)

type SSHKey struct {
	PrivateKey  string // Name to associate with private key
	Fingerprint string // Name to associate with fingerprint
}

func GenerateSSHKey(secrets *v1.Secret, key SSHKey) {
	secretKey := util.ConvertNameToKey(key.PrivateKey)
	fingerprintKey := util.ConvertNameToKey(key.Fingerprint)

	// Only create keys, don't update them
	if len(secrets.Data[secretKey]) > 0 {
		return
	}

	log.Printf("- SSH priK: %s\n", key.PrivateKey)

	// generate private key
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	privateBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(private),
	}

	// generate MD5 fingerprint
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// PEM encode private key
	secrets.Data[secretKey] = pem.EncodeToMemory(privateBlock)
	secrets.Data[fingerprintKey] = []byte(ssh.FingerprintLegacyMD5(public))
}

func RecordSSHKeyInfo(keys map[string]SSHKey, configVar *model.ConfigurationVariable) {
	// Get or create the key from the map, there should always be
	// a pair of private keys and fingerprints
	key := keys[configVar.Generator.ID]

	if configVar.Generator.ValueType == model.ValueTypeFingerprint {
		key.Fingerprint = configVar.Name
	} else if configVar.Generator.ValueType == model.ValueTypePrivateKey {
		key.PrivateKey = configVar.Name
	}

	keys[configVar.Generator.ID] = key
}
