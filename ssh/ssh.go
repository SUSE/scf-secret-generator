package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
	"k8s.io/api/core/v1"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/util"
)

// Key describes a key/fingerprint pair
type Key struct {
	PrivateKey  string // Name to associate with private key
	Fingerprint string // Name to associate with fingerprint
}

// GenerateKeys will create a private key and fingerprint
func GenerateKeys(keys map[string]Key, secrets *v1.Secret) error {
	for id, key := range keys {
		if len(key.PrivateKey) == 0 {
			return fmt.Errorf("No private key name defined for SSH id `%s`", id)
		}
		if len(key.Fingerprint) == 0 {
			return fmt.Errorf("No fingerprint name defined for SSH id `%s`", id)
		}
		err := generateKey(secrets, key)
		if err != nil {
			return err
		}
	}
	return nil
}

// generateKey will create a private key and fingerprint
func generateKey(secrets *v1.Secret, key Key) error {
	secretKey := util.ConvertNameToKey(key.PrivateKey)
	fingerprintKey := util.ConvertNameToKey(key.Fingerprint)

	// Only create keys, don't update them
	if len(secrets.Data[secretKey]) > 0 {
		return nil
	}

	log.Printf("- SSH priK: %s\n", key.PrivateKey)

	// generate private key
	private, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	privateBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(private),
	}

	// generate MD5 fingerprint
	public, err := ssh.NewPublicKey(&private.PublicKey)
	if err != nil {
		return err
	}

	// PEM encode private key
	secrets.Data[secretKey] = pem.EncodeToMemory(privateBlock)
	secrets.Data[fingerprintKey] = []byte(ssh.FingerprintLegacyMD5(public))

	return nil
}

// RecordKeyInfo records priave key or fingerprint names for later generation
func RecordKeyInfo(keys map[string]Key, configVar *model.ConfigurationVariable) {
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
