package secrets

import (
	"fmt"
	"log"
	"os"

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

// The unversioned name of the secret used by legacy versions of the secrets generator
const legacySecretName = "secret"

// The name of the secrets configmap
const secretsConfigMapName = "secrets-config"

const currentSecretName = "current-secrets-name"
const currentSecretGeneration = "current-secrets-generation"
const previousSecretName = "previous-secrets-name"

// SecretGenerator contains all global state for creating new secrets
type SecretGenerator struct {
	Namespace           string
	ServiceDomainSuffix string
	SecretsName         string
	SecretsGeneration   string
}

// Generate will fetch the current secrets, generate any missing values, and writes the new secrets
// under a new name. Then it updates the secrets configmap to describe the updated status quo.
func (sg *SecretGenerator) Generate(manifestFile string) {
	c, err := sg.getConfigMapInterface()
	if err != nil {
		log.Fatal(err)
	}
	s, err := sg.getSecretInterface()
	if err != nil {
		log.Fatal(err)
	}

	configMap := sg.getSecretConfig(c)
	secret, err := sg.getSecret(s, configMap)
	if err != nil {
		log.Fatal(err)
	}
	if secret != nil {
		file, err := os.Open(manifestFile)
		if err != nil {
			log.Fatal(err)
		}
		manifest, err := model.GetManifest(file)
		if err != nil {
			log.Fatal(err)
		}
		err = sg.generateSecret(manifest, secret, configMap)
		if err != nil {
			log.Fatal(err)
		}
		err = sg.updateSecret(s, secret, c, configMap)
		if err != nil {
			log.Fatal(err)
		}
	}
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

// GetConfigMapInterface returns a configmap interface for the KUBERNETES_NAMESPACE
func (sg *SecretGenerator) getConfigMapInterface() (configMapInterface, error) {
	clientset, err := kubeClientset()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().ConfigMaps(sg.Namespace), nil
}

// GetSecretInterface returns a secrets interface for the KUBERNETES_NAMESPACE
func (sg *SecretGenerator) getSecretInterface() (secretInterface, error) {
	clientset, err := kubeClientset()
	if err != nil {
		return nil, err
	}
	return clientset.CoreV1().Secrets(sg.Namespace), nil
}

// GetSecretConfig returns the configmap containing the secrets configuration
func (sg *SecretGenerator) getSecretConfig(c configMapInterface) *v1.ConfigMap {
	configMap, err := c.Get(secretsConfigMapName, metav1.GetOptions{})
	if err != nil {
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: secretsConfigMapName,
			},
			Data: map[string]string{},
		}
		configMap.Data[currentSecretName] = legacySecretName
		configMap.Data[currentSecretGeneration] = "0"
	}
	return configMap
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
		// This is a new installation, so make sure the configmap is created, not updated
		configMap.Data[currentSecretName] = ""
	}

	return newSecret, nil
}

// GenerateSecret will generate all secrets defined in the manifest that don't already exist
// in the secret. If secrets rotation is triggered, then all secrets not marked as immutable
// in the manifest will be regenerated.
func (sg *SecretGenerator) generateSecret(manifest model.Manifest, secrets *v1.Secret, configMap *v1.ConfigMap) error {
	if sg.SecretsGeneration != configMap.Data[currentSecretGeneration] {
		log.Printf("Rotating secrets; generation '%s' -> '%s'\n", configMap.Data[currentSecretGeneration], sg.SecretsGeneration)

		immutable := make(map[string]bool)
		for _, configVar := range manifest.Configuration.Variables {
			immutable[util.ConvertNameToKey(configVar.Name)] = configVar.Immutable
		}
		for name := range secrets.Data {
			if !immutable[name] {
				log.Printf("  Resetting %s\n", name)
				delete(secrets.Data, name)
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

	ssl.GenerateCerts(certInfo, sg.Namespace, sg.ServiceDomainSuffix, secrets)

	// remove all secrets no longer referenced in the manifest
	generatedSecret := make(map[string]bool)
	for _, configVar := range manifest.Configuration.Variables {
		generatedSecret[util.ConvertNameToKey(configVar.Name)] = configVar.Secret && configVar.Generator != nil
	}
	for name := range secrets.Data {
		if !generatedSecret[name] {
			delete(secrets.Data, name)
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
	if configMap.Data[previousSecretName] == "" {
		_, err = c.Create(configMap)
		if err != nil {
			return fmt.Errorf("Error creating configmap %s: %s", configMap.Name, err)
		}
		log.Printf("Created configmap `%s`\n", configMap.Name)
	} else {
		log.Printf("previous secret `%s`\n", configMap.Data[previousSecretName])
		_, err = c.Update(configMap)
		if err != nil {
			return fmt.Errorf("Error updating configmap %s: %s", configMap.Name, err)
		}
		log.Printf("Updated configmap `%s`\n", configMap.Name)
	}

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
		for _, previousName := range configVar.PreviousNames {
			previousValue := secrets.Data[util.ConvertNameToKey(previousName)]
			if len(previousValue) > 0 {
				secrets.Data[name] = previousValue
				return
			}
		}
	}
}
