package model

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
	"text/template"

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

// CertParams was copied from config-server/types/certificate_generator.go for on the fly parsing of certificate options
type CertParams struct {
	AlternativeNames []string `yaml:"alternative_names" json:"subject_names,omitempty"`
	IsCA             bool     `yaml:"is_ca"`
	AppendKubeCA     bool     `yaml:"append_kube_ca"`
	CAName           string   `yaml:"ca"`
	ExtKeyUsage      []string `yaml:"extended_key_usage"`
}

// GetManifest loads a manifest from file or string
func GetManifest(r io.Reader, env map[string]string) (Manifest, error) {
	var manifest Manifest

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return manifest, err
	}

	// Read raw (no schema) manifest so we can expand templates in the variables section.
	var raw map[string]interface{}
	err = yaml.Unmarshal(data, &raw)
	if err != nil {
		return manifest, err
	}
	if raw["variables"] == nil {
		return manifest, errors.New("'variables' section not found in manifest")
	}

	_, err = expandTemplates(raw["variables"], env)
	if err != nil {
		return manifest, err
	}

	// Turn manifest with expanded templates back into a string and unmarshal using manifest schema.
	data, err = yaml.Marshal(raw)
	if err != nil {
		return manifest, err
	}
	err = yaml.Unmarshal(data, &manifest)
	if err != nil {
		return manifest, err
	}

	// Validate that we have no duplicate variable names.
	seen := make(map[string]bool)
	for _, v := range manifest.Variables {
		if seen[v.Name] {
			return manifest, errors.New("Duplicate variable name found in manifest")
		}
		seen[v.Name] = true
	}

	// Parse Options using the CVOptions schema.
	for i, v := range manifest.Variables {
		str, err := yaml.Marshal(v.Options)
		if err != nil {
			return manifest, err
		}
		err = yaml.Unmarshal(str, &manifest.Variables[i].CVOptions)
		if err != nil {
			return manifest, err
		}
	}

	return manifest, err
}

// Walk the tree and expand templates in-place in all string nodes.
func expandTemplates(node interface{}, env map[string]string) (interface{}, error) {
	if node == nil {
		// Must return `node` here to get a "typed nil".
		return node, nil
	}

	switch reflect.TypeOf(node).Kind() {
	case reflect.Map:
		valueOf := reflect.ValueOf(node)
		for _, key := range valueOf.MapKeys() {
			elem := valueOf.MapIndex(key).Interface()
			if elem != nil {
				newNode, err := expandTemplates(elem, env)
				if err != nil {
					return nil, err
				}
				if newNode == nil {
					valueOf.SetMapIndex(key, reflect.Zero(valueOf.MapIndex(key).Type()))
				} else {
					valueOf.SetMapIndex(key, reflect.ValueOf(newNode))
				}
			}
		}
		return valueOf.Interface(), nil

	case reflect.Slice:
		valueOf := reflect.ValueOf(node)
		for i := 0; i < valueOf.Len(); i++ {
			elemValue := valueOf.Index(i)
			newNode, err := expandTemplates(elemValue.Interface(), env)
			if err != nil {
				return nil, err
			}
			if newNode == nil {
				elemValue.Set(reflect.Zero(elemValue.Type()))
			} else {
				elemValue.Set(reflect.ValueOf(newNode))
			}
		}
		return valueOf.Interface(), nil

	case reflect.String:
		str := node.(string)
		if strings.Contains(str, "{{") {
			t, err := template.New("").Parse(str)
			if err != nil {
				return nil, fmt.Errorf("Can't parse template in `%s`: %v", str, err)
			}
			buf := &bytes.Buffer{}
			err = t.Execute(buf, env)
			if err != nil {
				return nil, err
			}
			// If the string is a template expression from start to end, then run the
			// result through YAML parsing again to allow the result to change type
			// from string to boolean/number/null.
			if strings.HasPrefix(str, "{{") && strings.HasSuffix(str, "}}") {
				var data interface{}
				err = yaml.Unmarshal(buf.Bytes(), &data)
				return data, err
			}
			return buf.String(), nil
		}
	}

	return node, nil
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
