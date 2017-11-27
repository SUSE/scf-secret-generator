package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"

	"golang.org/x/crypto/ssh"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
)

type SSHKey struct {
	PrivateKey  string // Name to associate with private key
	Fingerprint string // Name to associate with fingerprint
}

func GenerateSSHKey(secretData map[string][]byte, updateData map[string][]byte, key SSHKey) bool {
	secretKey := util.ConvertNameToKey(key.PrivateKey)
	fingerprintKey := util.ConvertNameToKey(key.Fingerprint)

	// Only create keys, don't update them
	if _, ok := secretData[secretKey]; ok {
		return false
	}

	// Prefer user supplied update data over generating the keys ourselves
	if _, ok := updateData[secretKey]; ok {
		if _, ok := updateData[fingerprintKey]; !ok {
			log.Fatalf("Update include %s but not %s", secretKey, fingerprintKey)
		}
		secretData[secretKey] = updateData[secretKey]
		secretData[fingerprintKey] = updateData[fingerprintKey]
		return true
	}

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
	secretData[secretKey] = pem.EncodeToMemory(&privateBlock)

	// generate MD5 fingerprint
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	secretData[fingerprintKey] = []byte(ssh.FingerprintLegacyMD5(public))
	return true
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
