package secret

import (
	"log"
	"os"
	"regexp"

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

var secretPattern = regexp.MustCompile(SECRET_NAME+"-[0-9]+")

var kubeClusterConfig = rest.InClusterConfig
var kubeNewClient = kubernetes.NewForConfig
var logFatal = log.Fatal
var getEnv = os.Getenv

type secretInterface interface {
	Create(*v1.Secret) (*v1.Secret, error)
	Get(name string, options metav1.GetOptions) (*v1.Secret, error)
	Update(*v1.Secret) (*v1.Secret, error)
        List(opts metav1.ListOptions) (*v1.SecretList, error)
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

func UpdateSecrets(s secretInterface, secrets *v1.Secret, create bool) {
	if create {
		util.MarkAsClean(secrets)
		_, err := s.Create(secrets)
		if err != nil {
			logFatal(err)
		}
		log.Printf("Created `%s`\n", secrets.Name)
	} else if util.IsDirty(secrets) {
		util.MarkAsClean(secrets)
		_, err := s.Update(secrets)
		if err != nil {
			logFatal(err)
		}
		log.Printf("Updated `%s`\n", secrets.Name)
	}
}

func FindSecret(s secretInterface) (*v1.Secret, error) {
	slist, err := s.List (metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var best v1.Secret
	for _, s := range slist.Items {
		if (s.Name != SECRET_NAME) && !secretPattern.MatchString(s.Name) {
			// We allow only
			// - SECRET_NAME exactly
			// - names matching <SECRET_NAME>-\d+
			// This excludes all secrets with letters after the SECRET_NAME.
			continue
		}

		// s is now a secret which either matches
		// SECRET_NAME-*, or is exactly SECRET_NAME.

		if (best.Name == "") ||
			(len(s.Name) > len (best.Name)) ||
			(s.Name > best.Name) {
			// Notes on the logic above.  It assumes that
			// the names we deal with are of the form
			// `foo-V` where V is an integer number
			// without leading 0's, and the `foo` is the
			// across all considered secrets (true, foo =
			// SECRET_NAME)
			//
			// A secret is take as the new best if it
			// either the first, or its V is greater than
			// the V of the current best.
			//
			// - A longer name indicates a longer V, that
			//   is larger (*). This relies on the `no
			//   leading 0's` part.
			//
			// - For V's of the same length the lexico-
			//   graphical order is identical to the
			//   numeric order. This also relies on the
			//   `no leading 0's` part.
			//
			// (*) The special case where the name is just
			// `foo` is handled by this as well, as a
			// zero-length V which is less than anything
			// else and thus only used when nothing else
			// is present, in line with `foo` being the
			// last resort fallback.

			best = s
		}
	}

	if best.Name != "" {
		return &best, nil
	}
	return nil, errors.NewNotFound(v1.Resource("secret"), SECRET_NAME)
}

func GetOrCreateSecrets(s secretInterface) (create bool, secrets, updates *v1.Secret) {
	secretUpdateName := SECRET_UPDATE_NAME
	secretName := SECRET_NAME
	releaseRevision := getEnv("RELEASE_REVISION")
	if releaseRevision != "" {
		secretUpdateName += "-" + releaseRevision
		secretName += "-" + releaseRevision
	}

	log.Printf("Checking for chart-provided `%s`\n", secretUpdateName)

	// secret updates *must* exist
	updates, err := s.Get(secretUpdateName, metav1.GetOptions{})
	if err != nil {
		logFatal(err)
		return false, nil, nil
	}

	log.Println("Now ready to generate secrets")

	// check for existing secret, initialize a new Secret if not found
	secrets, err = FindSecret(s)
	if err != nil {
		if errors.IsNotFound(err) {
			log.Printf("No previous secret found, will create `%s`\n",
				secretName)

			create = true
			secrets = &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
				},
				Data: map[string][]byte{},
			}
		} else {
			logFatal(err)
			return false, nil, nil
		}
	} else {
		if secrets.Name != secretName {
			// The structure was imported and the
			// destination to write to is different than
			// what we got (per the names). Force creation.

			log.Printf("Imported previous secret `%s`, will create `%s`\n",
				secrets.Name, secretName)

			create = true

			// Note that the imported structure has its
			// field `ResourceVersion` set. That makes it
			// unsuitable for use with `Create`.  `Create`
			// actually rejects it and aborts the process.

			// The field is noted as read-only, we cannot
			// unset it.  We deal with the situation by
			// creating a fresh structure, i.e. without
			// `ResourceVersion` set, and give it a copy
			// of the imported data (and the destination
			// name, of course).
			newsecrets := &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
				},
				Data: secrets.Data,
			}
			secrets = newsecrets
		} else {
			log.Printf("Imported secret `%s`, will update\n",
				secrets.Name)
		}
	}

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
		util.MarkAsDirty(secrets)
	}
}

func migrateRenamedVariable(secrets *v1.Secret, configVar *model.ConfigurationVariable) {
	name := util.ConvertNameToKey(configVar.Name)
	if len(secrets.Data[name]) == 0 {
		for _, previousName := range configVar.PreviousNames {
			previousValue := secrets.Data[util.ConvertNameToKey(previousName)]
			if len(previousValue) > 0 {
				secrets.Data[name] = previousValue
				util.MarkAsDirty(secrets)
				return
			}
		}
	}
}
