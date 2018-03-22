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

var kubeClusterConfig = rest.InClusterConfig
var kubeNewClient = kubernetes.NewForConfig

// SecretGenerator contains all global state for creating new secrets
type SecretGenerator struct {
	Fatal  func(v ...interface{})
	Getenv func(key string) string
}

// NewSecretGenerator returns an instance of the SecretGenerator
func NewSecretGenerator() SecretGenerator {
	return SecretGenerator{
		Fatal:  log.Fatal,
		Getenv: os.Getenv,
	}
}

// ConfigMapInterface is a subset of v1.ConfigMapInterface
type ConfigMapInterface interface {
	Create(*v1.ConfigMap) (*v1.ConfigMap, error)
	Get(name string, options metav1.GetOptions) (*v1.ConfigMap, error)
	Update(*v1.ConfigMap) (*v1.ConfigMap, error)
	Delete(name string, options *metav1.DeleteOptions) error
}

// SecretInterface is a subset of v1.SecretInterface
type SecretInterface interface {
	Create(*v1.Secret) (*v1.Secret, error)
	Get(name string, options metav1.GetOptions) (*v1.Secret, error)
	Update(*v1.Secret) (*v1.Secret, error)
	Delete(name string, options *metav1.DeleteOptions) error
}

func kubeClientset() (*kubernetes.Clientset, error) {
	// Set up access to the kube API
	var clientset *kubernetes.Clientset
	kubeConfig, err := kubeClusterConfig()
	if err == nil {
		clientset, err = kubeNewClient(kubeConfig)
	}
	return clientset, err
}

// GetConfigMapInterface returns a configmap interface for the KUBERNETES_NAMESPACE
func (sg *SecretGenerator) GetConfigMapInterface() ConfigMapInterface {
	clientset, err := kubeClientset()
	if err != nil {
		sg.Fatal(err)
		return nil
	}
	return clientset.CoreV1().ConfigMaps(sg.Getenv("KUBERNETES_NAMESPACE"))
}

// GetSecretInterface returns a secrets interface for the KUBERNETES_NAMESPACE
func (sg *SecretGenerator) GetSecretInterface() SecretInterface {
	clientset, err := kubeClientset()
	if err != nil {
		sg.Fatal(err)
		return nil
	}
	return clientset.CoreV1().Secrets(sg.Getenv("KUBERNETES_NAMESPACE"))
}

// GetSecretConfig returns the configmap containing the secrets configuration
func (sg *SecretGenerator) GetSecretConfig(c ConfigMapInterface) *v1.ConfigMap {
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
func (sg *SecretGenerator) GetSecret(s SecretInterface, configMap *v1.ConfigMap) *v1.Secret {
	currentName := configMap.Data[currentSecretName]

	newName := sg.Getenv("KUBE_SECRETS_GENERATION_NAME")
	if newName == "" {
		sg.Fatal("KUBE_SECRETS_GENERATION_NAME is missing or empty.")
		return nil
	}
	if newName == currentName {
		log.Printf("Secret `%s` already exists; nothing to do\n", newName)
		return nil
	}

	newSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: newName,
		},
		Data: map[string][]byte{},
	}

	currentSecret, err := s.Get(currentName, metav1.GetOptions{})
	if err == nil {
		newSecret.Data = currentSecret.Data
	} else {
		if currentName != legacySecretName {
			sg.Fatal(fmt.Sprintf("Cannot get previous version of secrets using name '%s'.", currentName))
			return nil
		}
		// This is a new installation, so make sure the configmap is created, not updated
		configMap.Data[currentSecretName] = ""
	}

	return newSecret
}

// GenerateSecret will generate all secrets defined in the manifest that don't already exist
// in the secret. If secrets rotation is triggered, then all secrets not marked as immutable
// in the manifest will be regenerated.
func (sg *SecretGenerator) GenerateSecret(manifest model.Manifest, secrets *v1.Secret, configMap *v1.ConfigMap) {
	secretsGeneration := sg.Getenv("KUBE_SECRETS_GENERATION_COUNTER")
	if secretsGeneration == "" {
		sg.Fatal("KUBE_SECRETS_GENERATION_COUNTER is missing or empty.")
		return
	}

	if secretsGeneration != configMap.Data[currentSecretGeneration] {
		log.Printf("Rotating secrets; generation '%s' -> '%s'\n", configMap.Data[currentSecretGeneration], secretsGeneration)

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
		configMap.Data[currentSecretGeneration] = secretsGeneration
	}

	sshKeys := make(map[string]ssh.Key)

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
			ssl.RecordCertInfo(configVar)

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

	ssl.GenerateCerts(secrets)

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
}

// UpdateSecret creates the new Secret object and records the new name in the configmap.
// The current secrets become the previous secrets, and any previous previous secrets will
// be deleted. The configmap object in Kube is then updated to match the new configuration.
func (sg *SecretGenerator) UpdateSecret(s SecretInterface, secrets *v1.Secret, c ConfigMapInterface, configMap *v1.ConfigMap) {
	var obsoleteSecretName = configMap.Data[previousSecretName]
	configMap.Data[previousSecretName] = configMap.Data[currentSecretName]
	configMap.Data[currentSecretName] = secrets.Name

	// create new secret
	_, err := s.Create(secrets)
	if err != nil {
		sg.Fatal(fmt.Sprintf("Error creating secret %s: %s", secrets.Name, err))
	}
	log.Printf("Created secret `%s`\n", secrets.Name)

	// update configmap
	if configMap.Data[previousSecretName] == "" {
		_, err = c.Create(configMap)
		if err != nil {
			sg.Fatal(fmt.Sprintf("Error creating configmap %s: %s", configMap.Name, err))
		}
		log.Printf("Created configmap `%s`\n", configMap.Name)
	} else {
		log.Printf("previous secret `%s`\n", configMap.Data[previousSecretName])
		_, err = c.Update(configMap)
		if err != nil {
			sg.Fatal(fmt.Sprintf("Error updating configmap %s: %s", configMap.Name, err))
		}
		log.Printf("Updated configmap `%s`\n", configMap.Name)
	}

	if obsoleteSecretName != "" {
		err = s.Delete(obsoleteSecretName, &metav1.DeleteOptions{})
		if err != nil {
			log.Printf(fmt.Sprintf("Error deleting secret %s: %s", obsoleteSecretName, err))
		}
	}
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
