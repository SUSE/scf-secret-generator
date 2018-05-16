package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"strings"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/password"
	"github.com/SUSE/scf-secret-generator/ssh"
	"github.com/SUSE/scf-secret-generator/ssl"
	"github.com/SUSE/scf-secret-generator/util"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The name of the secrets configmap
const defaultSecretsConfigMapName = "secrets-config"

// The unversioned name of the secret used by legacy versions of the secrets generator
const legacySecretName = "secret"

const currentSecretName = "current-secrets-name"
const currentSecretGeneration = "current-secrets-generation"
const previousSecretName = "previous-secrets-name"
const configVersion = "config-version"

const currentConfigVersion = "1"

// The generatorInputSuffix is appended to a secret name to store the generator config used to create the current value
const generatorInputSuffix = ".generator"

// SecretGenerator contains all global state for creating new secrets
type SecretGenerator struct {
	Domain               string
	Namespace            string
	ServiceDomainSuffix  string
	SecretsName          string
	SecretsGeneration    string
	SecretsConfigMapName string
	CertExpiration       int
}

// Generate will fetch the current secrets, generate any missing values, and writes the new secrets
// under a new name. Then it updates the secrets configmap to describe the updated status quo.
func (sg *SecretGenerator) Generate(manifestReader io.Reader) error {
	c, err := sg.getConfigMapInterface()
	if err != nil {
		return err
	}
	s, err := sg.getSecretInterface()
	if err != nil {
		return err
	}
	if sg.SecretsConfigMapName == "" {
		sg.SecretsConfigMapName = defaultSecretsConfigMapName
	}
	configMap, err := sg.getSecretConfig(c)
	if err != nil {
		return err
	}
	secret, err := sg.getSecret(s, configMap)
	if err != nil {
		return err
	}
	if secret != nil {
		manifest, err := model.GetManifest(manifestReader)
		if err != nil {
			return err
		}
		err = sg.expandTemplates(manifest)
		if err != nil {
			return err
		}
		err = sg.generateSecret(manifest, secret, configMap)
		if err != nil {
			return err
		}
		err = sg.updateSecret(s, secret, c, configMap)
		if err != nil {
			return err
		}
	}
	return nil
}

// configMapInterface is a subset of v1.ConfigMapInterface
type configMapInterface interface {
	Create(*v1.ConfigMap) (*v1.ConfigMap, error)
	Get(name string, options metav1.GetOptions) (*v1.ConfigMap, error)
	Update(*v1.ConfigMap) (*v1.ConfigMap, error)
	Delete(name string, options *metav1.DeleteOptions) error
}

// secretInterface is a subset of v1.SecretInterface
type secretInterface interface {
	Create(*v1.Secret) (*v1.Secret, error)
	Get(name string, options metav1.GetOptions) (*v1.Secret, error)
	Update(*v1.Secret) (*v1.Secret, error)
	Delete(name string, options *metav1.DeleteOptions) error
}

func kubeClientset() (*kubernetes.Clientset, error) {
	// Set up access to the kube API
	var clientset *kubernetes.Clientset
	kubeConfig, err := rest.InClusterConfig()
	if err == nil {
		clientset, err = kubernetes.NewForConfig(kubeConfig)
	}
	return clientset, err
}

// GetConfigMapInterface returns a configmap interface for the namespace
func (sg *SecretGenerator) getConfigMapInterface() (configMapInterface, error) {
	clientset, err := kubeClientset()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().ConfigMaps(sg.Namespace), nil
}

// GetSecretInterface returns a secrets interface for the namespace
func (sg *SecretGenerator) getSecretInterface() (secretInterface, error) {
	clientset, err := kubeClientset()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().Secrets(sg.Namespace), nil
}

// defaultConfig returns the configmap containing the secrets configuration
func defaultConfig(name string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Data: map[string]string{
			configVersion:           currentConfigVersion,
			currentSecretName:       legacySecretName,
			currentSecretGeneration: "0",
		},
	}
}

// GetSecretConfig returns the configmap containing the secrets configuration
func (sg *SecretGenerator) getSecretConfig(c configMapInterface) (*v1.ConfigMap, error) {
	configMap, err := c.Get(sg.SecretsConfigMapName, metav1.GetOptions{})
	if err == nil && configMap.Data[configVersion] == "" {
		// Assume pre-release configMap without version is compatible with initial release
		// Setting configVersion here also tells updateSecret() that the configMap
		// needs to be updated and not created
		configMap.Data[configVersion] = currentConfigVersion
	}
	// So far there is only the initial config version
	if err == nil && configMap.Data[configVersion] != currentConfigVersion {
		return nil, fmt.Errorf("Config map `%s` has unsupported config version `%s`", configMap.Name, configMap.Data[configVersion])
	}
	if err == nil {
		// make sure we can later update the config map
		_, err = c.Update(configMap)
		if err != nil {
			log.Printf("Could get, but not update config map `%s`\n", configMap.Name)
		}
	} else {
		configMap = defaultConfig(sg.SecretsConfigMapName)
		_, err = c.Create(configMap)
		if err == nil {
			log.Printf("Created configmap `%s`\n", configMap.Name)
		}

	}
	return configMap, err
}

// GetSecret returns a new Secret object initialized with the data
// of the currently active secrets
func (sg *SecretGenerator) getSecret(s secretInterface, configMap *v1.ConfigMap) (*v1.Secret, error) {
	currentName := configMap.Data[currentSecretName]

	if sg.SecretsName == currentName {
		log.Printf("Secret `%s` already exists; nothing to do\n", sg.SecretsName)
		return nil, nil
	}

	newSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: sg.SecretsName,
		},
		Data: map[string][]byte{},
	}

	currentSecret, err := s.Get(currentName, metav1.GetOptions{})
	if err == nil {
		newSecret.Data = currentSecret.Data
	} else {
		if currentName != legacySecretName {
			return nil, fmt.Errorf("Cannot get previous version of secrets using name '%s'", currentName)
		}
	}

	return newSecret, nil
}

func (sg *SecretGenerator) expandTemplates(manifest model.Manifest) error {
	mapping := map[string]string{
		"DOMAIN":                     sg.Domain,
		"KUBERNETES_NAMESPACE":       sg.Namespace,
		"KUBE_SERVICE_DOMAIN_SUFFIX": sg.ServiceDomainSuffix,
	}
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Generator == nil {
			continue
		}
		for index, name := range configVar.Generator.SubjectNames {
			t, err := template.New("").Parse(name)
			if err != nil {
				return fmt.Errorf("Can't parse subject name '%s' for config variable '%s': %s", name, configVar.Name, err)
			}
			buf := &bytes.Buffer{}
			err = t.Execute(buf, mapping)
			if err != nil {
				return err
			}
			configVar.Generator.SubjectNames[index] = buf.String()
		}
	}
	return nil
}

// GenerateSecret will generate all secrets defined in the manifest that don't already exist
// in the secret. If secrets rotation is triggered, then all secrets not marked as immutable
// in the manifest will be regenerated.
func (sg *SecretGenerator) generateSecret(manifest model.Manifest, secrets *v1.Secret, configMap *v1.ConfigMap) error {
	if sg.SecretsGeneration != configMap.Data[currentSecretGeneration] {
		log.Printf("Rotating secrets; generation '%s' -> '%s'\n", configMap.Data[currentSecretGeneration], sg.SecretsGeneration)

		immutable := make(map[string]bool)
		for _, configVar := range manifest.Configuration.Variables {
			name := util.ConvertNameToKey(configVar.Name)
			immutable[name] = configVar.Immutable
		}
		for name := range secrets.Data {
			if !immutable[name] && !strings.HasSuffix(name, generatorInputSuffix) {
				log.Printf("  Resetting %s\n", name)
				delete(secrets.Data, name)
				delete(secrets.Data, name+generatorInputSuffix)
			}
		}
		configMap.Data[currentSecretGeneration] = sg.SecretsGeneration
	}

	sshKeys := make(map[string]ssh.Key)
	certInfo := make(map[string]ssl.CertInfo)

	log.Println("Generate Passwords ...")

	for _, configVar := range manifest.Configuration.Variables {
		if !configVar.Secret || configVar.Generator == nil {
			continue
		}
		migrateRenamedVariable(secrets, configVar)

		// create normalized representation of generator input parameters. SubjectName templates
		// are already expanded; JSON marshaller sorts mapping keys and emits struct fields in
		// the same order as they are defined in the source code.
		generatorInput, err := json.Marshal(configVar.Generator)
		if err != nil {
			return fmt.Errorf("Can't convert `%s` generator config into JSON: %s", configVar.Name, err)
		}

		// if generator input has changed, then the secret needs to be regenerated
		name := util.ConvertNameToKey(configVar.Name)
		if !bytes.Equal(secrets.Data[name+generatorInputSuffix], generatorInput) {
			if configVar.Immutable {
				log.Printf("Warning: Generator options for `%s` have changed, but variable is immutable\n", configVar.Name)
			} else {
				log.Printf("Variable `%s` must be regenerated because the generator options have changed\n", configVar.Name)
				delete(secrets.Data, name)
				secrets.Data[name+generatorInputSuffix] = generatorInput
			}
		}

		switch configVar.Generator.Type {
		case model.GeneratorTypePassword:
			password.GeneratePassword(secrets, configVar.Name)

		case model.GeneratorTypeCACertificate, model.GeneratorTypeCertificate:
			ssl.RecordCertInfo(certInfo, configVar)

		case model.GeneratorTypeSSH:
			ssh.RecordKeyInfo(sshKeys, configVar)

		default:
			log.Printf("Warning: variable %s has unknown generator type %s\n", configVar.Name, configVar.Generator.Type)
		}
	}

	log.Println("Generate SSH ...")

	for _, key := range sshKeys {
		ssh.GenerateKey(secrets, key)
	}

	log.Println("Generate SSL ...")

	ssl.GenerateCerts(certInfo, sg.Namespace, sg.ServiceDomainSuffix, sg.CertExpiration, secrets)

	// remove all secrets no longer referenced in the manifest
	generatedSecret := make(map[string]bool)
	for _, configVar := range manifest.Configuration.Variables {
		generatedSecret[util.ConvertNameToKey(configVar.Name)] = configVar.Secret && configVar.Generator != nil
	}
	for name := range secrets.Data {
		if !generatedSecret[name] && !strings.HasSuffix(name, generatorInputSuffix) {
			delete(secrets.Data, name)
			delete(secrets.Data, name+generatorInputSuffix)
		}
	}

	log.Println("Done with generation")
	return nil
}

// UpdateSecret creates the new Secret object and records the new name in the configmap.
// The current secrets become the previous secrets, and any previous previous secrets will
// be deleted. The configmap object in Kube is then updated to match the new configuration.
func (sg *SecretGenerator) updateSecret(s secretInterface, secrets *v1.Secret, c configMapInterface, configMap *v1.ConfigMap) error {
	var obsoleteSecretName = configMap.Data[previousSecretName]
	configMap.Data[previousSecretName] = configMap.Data[currentSecretName]
	configMap.Data[currentSecretName] = secrets.Name

	// create new secret
	_, err := s.Create(secrets)
	if err != nil {
		return fmt.Errorf("Error creating secret %s: %s", secrets.Name, err)
	}
	log.Printf("Created secret `%s`\n", secrets.Name)

	// update configmap
	_, err = c.Update(configMap)
	if err != nil {
		return fmt.Errorf("Error updating configmap %s: %s", configMap.Name, err)
	}
	log.Printf("Updated configmap `%s`\n", configMap.Name)

	if obsoleteSecretName != "" {
		err = s.Delete(obsoleteSecretName, &metav1.DeleteOptions{})
		if err != nil {
			log.Printf(fmt.Sprintf("Error deleting secret %s: %s", obsoleteSecretName, err))
		}
	}
	return nil
}

func migrateRenamedVariable(secrets *v1.Secret, configVar *model.ConfigurationVariable) {
	name := util.ConvertNameToKey(configVar.Name)
	if len(secrets.Data[name]) == 0 {
		for _, previous := range configVar.PreviousNames {
			previousName := util.ConvertNameToKey(previous)
			previousValue := secrets.Data[previousName]
			if len(previousValue) > 0 {
				secrets.Data[name] = previousValue
				secrets.Data[name+generatorInputSuffix] = secrets.Data[previousName+generatorInputSuffix]
				return
			}
		}
	}
}
