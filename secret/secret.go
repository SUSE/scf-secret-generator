package secret

import (
	"log"
	"os"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/password"
	"github.com/SUSE/scf-secret-generator/ssh"
	"github.com/SUSE/scf-secret-generator/ssl"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// The name of the secret stored in the kube API
const SECRET_NAME = "secret"

var kubeClusterConfig = rest.InClusterConfig
var kubeNewClient = kubernetes.NewForConfig
var logFatal = log.Fatal

var passGenerate = password.GeneratePassword
var sshKeyGenerate = ssh.GenerateSSHKey
var recordSSHKeyInfo = ssh.RecordSSHKeyInfo

func GetSecretInterface() corev1.SecretInterface {
	// Set up access to the kube API
	kubeConfig, err := kubeClusterConfig()
	if err != nil {
		logFatal(err)
		return nil
	}

	clientSet, err := kubeNewClient(kubeConfig)
	if err != nil {
		logFatal(err)
		return nil
	}

	return clientSet.CoreV1().Secrets(os.Getenv("KUBERNETES_NAMESPACE"))
}

func UpdateSecrets(s corev1.SecretInterface, secrets *v1.Secret, create, dirty bool) {
	if create {
		_, err := s.Create(secrets)
		if err != nil {
			logFatal(err)
		}
		log.Println("Created `secret`")
	} else if dirty {
		_, err := s.Update(secrets)
		if err != nil {
			logFatal(err)
		}
		log.Println("Updated `secret`")
	}
}

func GetOrCreateSecrets(s corev1.SecretInterface) (create bool, secrets *v1.Secret) {
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
			logFatal(err)
		}
	}

	return
}

func GenerateSecrets(manifest model.Manifest, secrets *v1.Secret) (dirty bool) {
	sshKeys := make(map[string]ssh.SSHKey)

	// go over the list of variables and run the appropriate generator function
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret && configVar.Generator != nil {
			switch configVar.Generator.Type {
			case model.GeneratorTypePassword:
				dirty = passGenerate(secrets.Data, configVar.Name) || dirty

			case model.GeneratorTypeCACertificate, model.GeneratorTypeCertificate:
				ssl.RecordCertInfo(configVar)

			case model.GeneratorTypeSSH:
				recordSSHKeyInfo(sshKeys, configVar)
			}
		}
	}

	for _, key := range sshKeys {
		dirty = sshKeyGenerate(secrets.Data, key) || dirty
	}

	dirty = ssl.GenerateCerts(secrets) || dirty

	return
}
