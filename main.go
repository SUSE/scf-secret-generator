package main

import (
	"fmt"
	"io/ioutil"
	"log"
	//"time"

	"github.com/dchest/uniuri"
	"gopkg.in/yaml.v2"
	//"k8s.io/apimachinery/pkg/api/errors"
	//metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"k8s.io/client-go/kubernetes"
	//"k8s.io/client-go/rest"
)

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

func generatePassword(secretName string) error {
	password := uniuri.NewLen(64)

	fmt.Println(secretName, password)

	return nil
}

func main() {
	manifestFile, err := ioutil.ReadFile("role-manifest.yml")
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

	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret && configVar.Generator != nil {
			if configVar.Generator.Type == GeneratorTypePassword {
				if err = generatePassword(configVar.Name); err != nil {
					log.Fatal(err)
				}
			} else if configVar.Generator.Type == GeneratorTypeCACertificate {
			} else if configVar.Generator.Type == GeneratorTypeCertificate {
			} else if configVar.Generator.Type == GeneratorTypeSSH {
			}
		}
	}
}
