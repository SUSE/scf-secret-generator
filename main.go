package main

import (
	"fmt"
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
	"k8s.io/client-go/rest"
)

// The name of the secret stored in the kube API
const SECRET_NAME = "secret"

// GeneratorType describes the type of generator used for the configuration value
type GeneratorType string

// These are the available generator types for configuration values
const (
	GeneratorTypePassword      = GeneratorType("Password")      // Password
	GeneratorTypeSSH           = GeneratorType("SSH")           // SSH key
	GeneratorTypeCACertificate = GeneratorType("CACertificate") // CA Certificate
	GeneratorTypeCertificate   = GeneratorType("Certificate")   // Certificate
)

// ConfigurationVariableGenerator describes how to automatically generate values
// for a configuration variable
type ConfigurationVariableGenerator struct {
	ID        string        `yaml:"id"`
	Type      GeneratorType `yaml:"type"`
	ValueType string        `yaml:"value_type"`
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

func main() {
	if len(os.Args) != 2 {
		printHelp()
		os.Exit(1)
	}

	// Read the manifest file
	manifestFile, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	var manifest Manifest
	if err = yaml.Unmarshal(manifestFile, &manifest); err != nil {
		log.Fatal(err)
	}

	if manifest.Configuration == nil {
		log.Fatal("'configuration section' not found in manifest")
	}

	// Set up access to the kube API
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		panic(err.Error())
	}

	s := clientSet.CoreV1().Secrets(os.Getenv("KUBERNETES_NAMESPACE"))

	// check for existing secret, initialize a new Secret if not found
	create := false
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

	dirty := false

	// go over the list of variables and run the appropriate generator function
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret && configVar.Generator != nil {
			if configVar.Generator.Type == GeneratorTypePassword {
				dirty = generatePassword(secrets.Data, configVar.Name) || dirty
			} else if configVar.Generator.Type == GeneratorTypeCACertificate {
			} else if configVar.Generator.Type == GeneratorTypeCertificate {
			} else if configVar.Generator.Type == GeneratorTypeSSH {
			}
		}
	}

	// Create or update the secret
	if create {
		_, err = s.Create(secrets)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Created `secret`")
	} else if dirty {
		_, err = s.Update(secrets)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Updated `secret`")
	}
}
