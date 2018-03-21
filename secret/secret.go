package secret

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
const LEGACY_SECRETS_NAME = "secret"

// The name of the secrets configmap
const SECRETS_CONFIGMAP_NAME = "secrets-config"

const CURRENT_SECRETS_NAME = "current-secrets-name"
const CURRENT_SECRETS_GENERATION = "current-secrets-generation"
const PREVIOUS_SECRETS_NAME = "previous-secrets-name"

var kubeClusterConfig = rest.InClusterConfig
var kubeNewClient = kubernetes.NewForConfig
var logFatal = log.Fatal
var getEnv = os.Getenv

type configMapInterface interface {
	Create(*v1.ConfigMap) (*v1.ConfigMap, error)
	Get(name string, options metav1.GetOptions) (*v1.ConfigMap, error)
	Update(*v1.ConfigMap) (*v1.ConfigMap, error)
	Delete(name string, options *metav1.DeleteOptions) error
}

type secretInterface interface {
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

func GetConfigMapInterface() configMapInterface {
	clientset, err := kubeClientset()
	if err != nil {
		logFatal(err)
		return nil
	}
	return clientset.CoreV1().ConfigMaps(getEnv("KUBERNETES_NAMESPACE"))
}

func GetSecretInterface() secretInterface {
	clientset, err := kubeClientset()
	if err != nil {
		logFatal(err)
		return nil
	}
	return clientset.CoreV1().Secrets(getEnv("KUBERNETES_NAMESPACE"))
}

func GetSecretConfig(c configMapInterface) *v1.ConfigMap {
	configMap, err := c.Get(SECRETS_CONFIGMAP_NAME, metav1.GetOptions{})
	if err != nil {
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name: SECRETS_CONFIGMAP_NAME,
			},
			Data: map[string]string{},
		}
		configMap.Data[CURRENT_SECRETS_NAME] = LEGACY_SECRETS_NAME
		configMap.Data[CURRENT_SECRETS_GENERATION] = "0"
	}
	return configMap
}

func GetSecrets(s secretInterface, configMap *v1.ConfigMap) *v1.Secret {
	currentName := configMap.Data[CURRENT_SECRETS_NAME]

	newName := getEnv("KUBE_SECRETS_GENERATION_NAME")
	if newName == "" {
		logFatal("KUBE_SECRETS_GENERATION_NAME is missing or empty.")
		return nil
	}
	if newName == currentName {
		log.Printf("Secret `%s` already exists; nothing to do\n", newName)
		return nil
	}

	newSecrets := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: newName,
		},
		Data: map[string][]byte{},
	}

	currentSecrets, err := s.Get(currentName, metav1.GetOptions{})
	if err == nil {
		newSecrets.Data = currentSecrets.Data
	} else {
		if currentName != LEGACY_SECRETS_NAME {
			logFatal(fmt.Sprintf("Cannot get previous version of secrets using name '%s'.", currentName))
			return nil
		}
		// This is a new installation, so make sure the configmap is created, not updated
		configMap.Data[CURRENT_SECRETS_NAME] = ""
	}

	return newSecrets
}

func GenerateSecrets(manifest model.Manifest, secrets *v1.Secret, configMap *v1.ConfigMap) {
	secretsGeneration := getEnv("KUBE_SECRETS_GENERATION_COUNTER")
	if secretsGeneration == "" {
		logFatal("KUBE_SECRETS_GENERATION_COUNTER is missing or empty.")
		return
	}

	if secretsGeneration != configMap.Data[CURRENT_SECRETS_GENERATION] {
		log.Printf("Rotating secrets; generation '%s' -> '%s'\n", configMap.Data[CURRENT_SECRETS_GENERATION], secretsGeneration)
		for name := range secrets.Data {
			rotate := true
			for _, configVar := range manifest.Configuration.Variables {
				if name == util.ConvertNameToKey(configVar.Name) && configVar.Immutable {
					rotate = false
					break
				}
			}
			if rotate {
				log.Printf("  Resetting %s\n", name)
				delete(secrets.Data, name)
			}
		}
		configMap.Data[CURRENT_SECRETS_GENERATION] = secretsGeneration
	}

	sshKeys := make(map[string]ssh.SSHKey)

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
			ssh.RecordSSHKeyInfo(sshKeys, configVar)

		default:
			log.Printf("Warning: variable %s has unknown generator type %s\n", configVar.Name, configVar.Generator.Type)
		}
	}

	log.Println("Generate SSH ...")

	for _, key := range sshKeys {
		ssh.GenerateSSHKey(secrets, key)
	}

	log.Println("Generate SSL ...")

	ssl.GenerateCerts(secrets)

	// remove all secrets no longer referenced in the manifest
	for name := range secrets.Data {
		stillUsed := false
		for _, configVar := range manifest.Configuration.Variables {
			if configVar.Secret && configVar.Generator != nil && name == util.ConvertNameToKey(configVar.Name) {
				stillUsed = true
				break
			}
		}
		if !stillUsed {
			delete(secrets.Data, name)
		}
	}

	log.Println("Done with generation")
}

func UpdateSecrets(s secretInterface, secrets *v1.Secret, c configMapInterface, configMap *v1.ConfigMap) {
	var obsoleteSecretName = configMap.Data[PREVIOUS_SECRETS_NAME]
	configMap.Data[PREVIOUS_SECRETS_NAME] = configMap.Data[CURRENT_SECRETS_NAME]
	configMap.Data[CURRENT_SECRETS_NAME] = secrets.Name

	// create new secret
	_, err := s.Create(secrets)
	if err != nil {
		logFatal(fmt.Sprintf("Error creating secret %s: %s", secrets.Name, err))
	}
	log.Printf("Created secret `%s`\n", secrets.Name)

	// update configmap
	if configMap.Data[PREVIOUS_SECRETS_NAME] == "" {
		_, err = c.Create(configMap)
		if err != nil {
			logFatal(fmt.Sprintf("Error creating configmap %s: %s", configMap.Name, err))
		}
		log.Printf("Created configmap `%s`\n", configMap.Name)
	} else {
		log.Printf("previous secret `%s`\n", configMap.Data[PREVIOUS_SECRETS_NAME])
		_, err = c.Update(configMap)
		if err != nil {
			logFatal(fmt.Sprintf("Error updating configmap %s: %s", configMap.Name, err))
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
