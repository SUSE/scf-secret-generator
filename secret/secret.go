package secret

import (
	"log"
	"os"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/password"
	"github.com/SUSE/scf-secret-generator/ssh"
	"github.com/SUSE/scf-secret-generator/ssl"
	"github.com/SUSE/scf-secret-generator/util"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// The name of the secret stored in the kube API
const SECRET_NAME = "secret"

// The name of the secret updates stored in the kube API
const SECRET_UPDATE_NAME = "secret-update"

var kubeClusterConfig = rest.InClusterConfig
var kubeNewClient = kubernetes.NewForConfig
var logFatal = log.Fatal
var getEnv = os.Getenv

type secretInterface interface {
	Create(*v1.Secret) (*v1.Secret, error)
	Get(name string, options metav1.GetOptions) (*v1.Secret, error)
	Update(*v1.Secret) (*v1.Secret, error)
}

var passGenerate = password.GeneratePassword
var sshKeyGenerate = ssh.GenerateSSHKey
var recordSSHKeyInfo = ssh.RecordSSHKeyInfo
var recordSSLCertInfo = ssl.RecordCertInfo
var generateSSLCerts = ssl.GenerateCerts

func GetSecretInterface() secretInterface {
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

	return clientSet.CoreV1().Secrets(getEnv("KUBERNETES_NAMESPACE"))
}

func UpdateSecrets(s secretInterface, secrets *v1.Secret, create, dirty bool) {
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

func GetOrCreateSecrets(s secretInterface) (create bool, secrets *v1.Secret, updates *v1.Secret) {
	secretUpdateName := SECRET_UPDATE_NAME
	releaseRevision := getEnv("RELEASE_REVISION")
	if releaseRevision != "" {
		secretUpdateName += "-" + releaseRevision
	}

	// secret updates *must* exist
	updates, err := s.Get(secretUpdateName, metav1.GetOptions{})
	if err != nil {
		logFatal(err)
		return false, nil, nil
	}

	// check for existing secret, initialize a new Secret if not found
	secrets, err = s.Get(SECRET_NAME, metav1.GetOptions{})
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
			return false, nil, nil
		}
	}

	return
}

func GenerateSecrets(manifest model.Manifest, secrets *v1.Secret, updates *v1.Secret) (dirty bool) {
	sshKeys := make(map[string]ssh.SSHKey)

	// go over the list of variables and run the appropriate generator function
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret {
			if configVar.Generator == nil {
				dirty = updateVariable(secrets, updates, configVar) || dirty
			} else {
				switch configVar.Generator.Type {
				case model.GeneratorTypePassword:
					dirty = passGenerate(secrets.Data, updates.Data, configVar.Name) || dirty

				case model.GeneratorTypeCACertificate, model.GeneratorTypeCertificate:
					recordSSLCertInfo(configVar)

				case model.GeneratorTypeSSH:
					recordSSHKeyInfo(sshKeys, configVar)
				}
			}
		}
	}

	for _, key := range sshKeys {
		dirty = sshKeyGenerate(secrets.Data, updates.Data, key) || dirty
	}

	dirty = generateSSLCerts(secrets, updates) || dirty

	return
}

func updateVariable(secrets *v1.Secret, updates *v1.Secret, configVar *model.ConfigurationVariable) (dirty bool) {
	name := util.ConvertNameToKey(configVar.Name)
	if len(secrets.Data[name]) == 0 && len(updates.Data[name]) > 0 {
		secrets.Data[name] = updates.Data[name]
		dirty = true
	}
	return
}
