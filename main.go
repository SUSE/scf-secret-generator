package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// The name of the secret stored in the kube API
const SECRET_NAME = "secret-alex"

// GeneratorType describes the type of generator used for the configuration value
type GeneratorType string

// These are the available generator types for configuration values
const (
	GeneratorTypePassword      = GeneratorType("Password")      // Password
	GeneratorTypeSSH           = GeneratorType("SSH")           // SSH key
	GeneratorTypeCACertificate = GeneratorType("CACertificate") // CA Certificate
	GeneratorTypeCertificate   = GeneratorType("Certificate")   // Certificate
)

// ValueType describes the type of generator used for the configuration value
type ValueType string

// These are the available generator types for configuration values
const (
	ValueTypeFingerprint = ValueType("fingerprint")
	ValueTypePrivateKey  = ValueType("private_key")
)

// ConfigurationVariableGenerator describes how to automatically generate values
// for a configuration variable
type ConfigurationVariableGenerator struct {
	ID        string        `yaml:"id"`
	Type      GeneratorType `yaml:"type"`
	ValueType ValueType     `yaml:"value_type"`
	KeyLength int           `yaml:"key_length"`
}

// ConfigurationVariable is a configuration to be exposed to the IaaS
//
// Notes on the fields Type and Internal.
// 1. Type's legal values are `user` and `environment`.
//    `user` is default.
//
//    A `user` CV is rendered into k8s yml config files, etc. to make it available to roles who need it.
//    - An internal CV is rendered to all roles.
//    - A public CV is rendered only to the roles whose templates refer to the CV.
//
//    An `environment` CV comes from a script, not the user. Being
//    internal this way it is not rendered to any configuration files.
//
// 2. Internal's legal values are all YAML boolean values.
//    A public CV is used in templates
//    An internal CV is not, consumed in a script instead.
type ConfigurationVariable struct {
	Name        string                          `yaml:"name"`
	Default     interface{}                     `yaml:"default"`
	Description string                          `yaml:"description"`
	Example     string                          `yaml:"example"`
	Generator   *ConfigurationVariableGenerator `yaml:"generator"`
	Type        CVType                          `yaml:"type"`
	Internal    bool                            `yaml:"internal,omitempty"`
	Secret      bool                            `yaml:"secret,omitempty"`
	Required    bool                            `yaml:"required,omitempty"`
}

// CVType is the type of the configuration variable; see the constants below
type CVType string

const (
	// CVTypeUser is for user-specified variables (default)
	CVTypeUser = CVType("user")
	// CVTypeEnv is for script-specified variables
	CVTypeEnv = CVType("environment")
)

// Configuration contains information about how to configure the
// resulting images
type Configuration struct {
	Variables []*ConfigurationVariable `yaml:"variables"`
}

// Manifest is the top level of the role manifest file
type Manifest struct {
	Configuration *Configuration `yaml:"configuration"`
}

type SSHKey struct {
	Length      int
	PrivateKey  string // Name to associate with private key
	Fingerprint string // Name to associate with fingerprint
}

// generatePassword generates a password for `secretName` if it doesn't already exist
func generatePassword(secretData map[string][]byte, secretName string) bool {
	secretKey := strings.Replace(strings.ToLower(secretName), "_", "-", -1)

	// Only create keys, don't update them
	if _, ok := secretData[secretKey]; !ok {
		password := uniuri.NewLen(64)
		secretData[secretKey] = []byte(password)
		return true
	}

	return false
}

func printHelp() {
	fmt.Printf("Usage: %s <role-manifest>\n", os.Args[0])
}

func getManifest(name string) (manifest Manifest) {
	manifestFile, err := ioutil.ReadFile(name)
	if err != nil {
		log.Fatal(err)
	}

	if err = yaml.Unmarshal(manifestFile, &manifest); err != nil {
		log.Fatal(err)
	}

	if manifest.Configuration == nil {
		log.Fatal("'configuration section' not found in manifest")
	}

	return
}

func getSecrets() corev1.SecretInterface {
	// Set up access to the kube API
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Fatal(err)
	}

	return clientSet.CoreV1().Secrets(os.Getenv("KUBERNETES_NAMESPACE"))
}

func updateSecrets(s corev1.SecretInterface, secrets *v1.Secret, create, dirty bool) {
	if create {
		_, err := s.Create(secrets)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Created `secret`")
	} else if dirty {
		_, err := s.Update(secrets)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Updated `secret`")
	}
}

func getOrCreateSecret(s corev1.SecretInterface) (create bool, secrets *v1.Secret) {
	// check for existing secret, initialize a new Secret if not found
	secrets, err := s.Get(SECRET_NAME, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			log.Println("`secret` not found, creating")
			create = true

			secrets = &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: SECRET_NAME,
				},
				Data: map[string][]byte{},
			}
		} else {
			log.Fatal(err)
		}
	}

	return
}

func generateSSHKey(secretData map[string][]byte, key SSHKey) {

	log.Printf("Creating private key: %+v\n", key)

	// generate private key
	private, err := rsa.GenerateKey(rand.Reader, key.Length)
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

func parseSSHKey(keys map[string]SSHKey, configVar *ConfigurationVariable) {

	var key SSHKey

	if _, ok := keys[configVar.Generator.ID]; ok {
		key = keys[configVar.Generator.ID]
	}

	if configVar.Generator.ValueType == ValueTypeFingerprint {
		key.Fingerprint = configVar.Name
	} else if configVar.Generator.ValueType == ValueTypePrivateKey {
		key.PrivateKey = configVar.Name

		if configVar.Generator.KeyLength == 0 {
			key.Length = 4096
		} else {
			key.Length = configVar.Generator.KeyLength
		}
	}

	keys[configVar.Generator.ID] = key
}

func generateSecrets(manifest Manifest, secrets *v1.Secret) (dirty bool) {
	sshKeys := make(map[string]SSHKey)

	// go over the list of variables and run the appropriate generator function
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret && configVar.Generator != nil {
			if configVar.Generator.Type == GeneratorTypePassword {
				dirty = generatePassword(secrets.Data, configVar.Name) || dirty
			} else if configVar.Generator.Type == GeneratorTypeCACertificate {
			} else if configVar.Generator.Type == GeneratorTypeCertificate {
			} else if configVar.Generator.Type == GeneratorTypeSSH {
				parseSSHKey(sshKeys, configVar)
			}
		}
	}

	for _, key := range sshKeys {
		generateSSHKey(secrets.Data, key)
	}

	return
}

func main() {
	if len(os.Args) != 2 {
		printHelp()
		os.Exit(1)
	}

	manifest := getManifest(os.Args[1])

	s := getSecrets()

	create, secrets := getOrCreateSecret(s)

	dirty := generateSecrets(manifest, secrets)

	updateSecrets(s, secrets, create, dirty)
}
