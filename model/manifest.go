package model

import (
	"errors"
	"io"
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

// VariableType describes the BOSH type of the variable,
// as defined in https://bosh.io/docs/manifest-v2/#variables
type VariableType string

// These are the supported variable types for configuration values
// An EmptyType will be ignored by variable generation.
const (
	EmptyType               = VariableType("") // type is required
	VariableTypeCertificate = VariableType("certificate")
	VariableTypeSSH         = VariableType("ssh")
	VariableTypePassword    = VariableType("password")
)

// KeySuffix is appended to the name of certificate variables private key secret
const KeySuffix = "_KEY"

// FingerprintSuffix is appended to the name of SSH variables fingerprint secret
const FingerprintSuffix = "_FINGERPRINT"

// Manifest is the top level of the role manifest file
// Variables contains information about how to configure the
// resulting images
type Manifest struct {
	Variables Variables `yaml:"variables"`
}

// Variables from the BOSH manifests variables section
type Variables []*VariableDefinition

// VariableDefinition is a configuration to be exposed to the IaaS
//
// Type is the type of a variable.
// Options are free form as defined in https://bosh.io/docs/manifest-v2/#variables
// CVOptions are additional options, mostly used to control the generated k8s secrets
type VariableDefinition struct {
	Name      string          `yaml:"name"`
	Type      VariableType    `json:"type" yaml:"type"`
	Options   VariableOptions `yaml:"options"`
	CVOptions CVOptions
}

// VariableOptions are not structured, their content depends on the type
type VariableOptions map[string]interface{}

// CVOptions are custom options, mostly used to control the generated k8s secrets
type CVOptions struct {
	PreviousNames []string `yaml:"previous_names"`
	Secret        bool     `yaml:"secret,omitempty"`
	Immutable     bool     `yaml:"immutable,omitempty"`
	RoleName      string   `json:"role_name,omitempty" yaml:"role_name,omitempty"`
}

// Internal structure for extracting our CVOptions into a struct
type internalConfigurationVariable struct {
	CVOptions CVOptions `yaml:"options"`
}

// Since we want all keys below options: but still need access to a number of fissile special
// options.
type internalVariableDefinitions struct {
	Variables []*internalConfigurationVariable `yaml:"variables"`
}

// CertParams was copied from config-server/types/certificate_generator.go for on the fly parsing of certificate options
type CertParams struct {
	CommonName       string   `yaml:"common_name"`
	AlternativeNames []string `yaml:"alternative_names" json:"subject_names,omitempty"`
	IsCA             bool     `yaml:"is_ca"`
	CAName           string   `yaml:"ca"`
	ExtKeyUsage      []string `yaml:"extended_key_usage"`
}

// GetManifest loads a manifest from file or string
func GetManifest(r io.Reader) (Manifest, error) {
	var manifest Manifest

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return manifest, err
	}

	err = yaml.Unmarshal(data, &manifest)
	if err != nil {
		return manifest, err
	}

	if err == nil && manifest.Variables == nil {
		return manifest, errors.New("'Variables section' not found in manifest")
	}

	seen := make(map[string]bool)
	for _, v := range manifest.Variables {
		if seen[v.Name] {
			return manifest, errors.New("Duplicate variable name found in manifest")
		}
		seen[v.Name] = true
	}

	// clean up, since we parse these into CVOptions
	for _, v := range manifest.Variables {
		delete(v.Options, "previous_names")
		delete(v.Options, "generator")
		delete(v.Options, "secret")
		delete(v.Options, "immutable")
		delete(v.Options, "role_name")
	}

	var definitions internalVariableDefinitions
	err = yaml.Unmarshal(data, &definitions)
	if err != nil {
		return manifest, err
	}

	for i, v := range definitions.Variables {
		manifest.Variables[i].CVOptions = v.CVOptions
	}

	return manifest, err
}

// OptionsAsCertificateParams returns the variables options as a struct of certificate parameters
func (cv *VariableDefinition) OptionsAsCertificateParams() (CertParams, error) {
	params := CertParams{}
	valBytes, err := yaml.Marshal(cv.Options)
	if err != nil {
		return params, err
	}

	err = yaml.Unmarshal(valBytes, &params)
	if err != nil {
		return params, err
	}

	return params, nil
}

// SetOptions updates the variables options from the certificate parameters
func (cv *VariableDefinition) SetOptions(params interface{}) error {
	str, err := yaml.Marshal(params)
	if err != nil {
		return err
	}

	options := VariableOptions{}
	err = yaml.Unmarshal(str, &options)
	if err != nil {
		return err
	}
	cv.Options = options
	return nil
}
