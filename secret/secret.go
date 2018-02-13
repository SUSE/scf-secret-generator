package secret

import (
	"fmt"
	"log"
	"os"
	"strconv"

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
	Delete(name string, options *metav1.DeleteOptions) error
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

func UpdateSecrets(s secretInterface, secrets *v1.Secret) {
	_, err := s.Create(secrets)
	if err != nil {
		logFatal(err)
	}
	log.Printf("Created `%s`\n", secrets.Name)
}

func FindPreviousSecret(s secretInterface, rv int) (*v1.Secret, error) {
	// Args: rv is the current release revision.
	// Logic
	// (1) if rv-2 exists, delete it (prevent leaking of too many old entities)
	// (2) if rv-1 exists take it
	// (3) if secret without rv exists, take it
	// (4) error

	// / / // /// ///// //////// ///////////// /////////////////////

	// (1) Delete really old entity (R-2), if it exists. We do not
	// care about errors.
	_ = s.Delete(SECRET_NAME + fmt.Sprintf("-%d", rv-2), &metav1.DeleteOptions{})

	// (2) Look for and take R-1
	previousSecret := SECRET_NAME + fmt.Sprintf("-%d", rv-1)
	secret, err := s.Get(previousSecret, metav1.GetOptions{})
	if err == nil {
		return secret, nil
	}

	// (3) Take unversioned secret, should we have it.
	secret, err = s.Get(SECRET_NAME, metav1.GetOptions{})
	if err == nil {
		return secret, nil
	}

	// (4) Neither R-1 nor unversioned available. Bail out.
	return nil, errors.NewNotFound(v1.Resource("secret"), previousSecret)
}

func CreateSecrets(s secretInterface) (secrets, updates *v1.Secret) {
	secretUpdateName := SECRET_UPDATE_NAME
	secretName := SECRET_NAME
	releaseRevision := getEnv("RELEASE_REVISION")

	if releaseRevision == "" {
		logFatal("RELEASE_REVISION is missing or empty.")
		return nil, nil
	}

	rv, err := strconv.Atoi(releaseRevision)
	if err != nil {
		logFatal(err)
		return nil, nil
	}

	secretUpdateName += "-" + releaseRevision
	secretName += "-" + releaseRevision

	log.Printf("Checking for chart-provided `%s`\n", secretUpdateName)

	// secret updates *must* exist
	updates, err = s.Get(secretUpdateName, metav1.GetOptions{})
	if err != nil {
		logFatal(err)
		return nil, nil
	}

	// We always create a new secret
	secrets = &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		Data: map[string][]byte{},
	}

	log.Println("Checking for previous secret")

	// Check for existing secret to use as baseline
	previousSecrets, err := FindPreviousSecret(s, rv)
	if err != nil && !errors.IsNotFound(err) {
		logFatal(err)
		return nil, nil
	}
	// Here: err == nil || errors.IsNotFound(err)
	if previousSecrets != nil {
		log.Printf("Importing previous secret `%s`\n", previousSecrets.Name)
		secrets.Data = previousSecrets.Data
	}

	log.Printf("Fill secret `%s`\n", secrets.Name)
	return
}

func GenerateSecrets(manifest model.Manifest, secrets, updates *v1.Secret) {
	sshKeys := make(map[string]ssh.SSHKey)

	log.Println("Generate Passwords ...")

	// go over the list of manifest variables and run the
	// appropriate generator function
	for _, configVar := range manifest.Configuration.Variables {
		if configVar.Secret {
			migrateRenamedVariable(secrets, configVar)
			if configVar.Generator == nil {
				updateVariable(secrets, updates, configVar)
			} else {
				switch configVar.Generator.Type {
				case model.GeneratorTypePassword:
					passGenerate(secrets, updates, configVar.Name)

				case model.GeneratorTypeCACertificate, model.GeneratorTypeCertificate:
					recordSSLCertInfo(configVar)

				case model.GeneratorTypeSSH:
					recordSSHKeyInfo(sshKeys, configVar)
				}
			}
		}
	}

	log.Println("Generate SSH ...")

	for _, key := range sshKeys {
		sshKeyGenerate(secrets, updates, key)
	}

	log.Println("Generate SSL ...")

	generateSSLCerts(secrets, updates)

	log.Println("Done with generation")
}

func updateVariable(secrets, updates *v1.Secret, configVar *model.ConfigurationVariable) {
	name := util.ConvertNameToKey(configVar.Name)
	if len(secrets.Data[name]) == 0 && len(updates.Data[name]) > 0 {
		secrets.Data[name] = updates.Data[name]
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
