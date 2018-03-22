package main

import (
	"fmt"
	"os"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/secrets"
)

func printHelp() {
	fmt.Printf("Usage: %s <role-manifest>\n", os.Args[0])
}

func main() {
	if len(os.Args) != 2 {
		printHelp()
		os.Exit(1)
	}

	manifest := model.GetManifest(os.Args[1])

	c := secrets.GetConfigMapInterface()
	s := secrets.GetSecretInterface()

	configMap := secrets.GetSecretConfig(c)
	secret := secrets.GetSecret(s, configMap)
	if secret != nil {
		secrets.GenerateSecret(manifest, secret, configMap)
		secrets.UpdateSecret(s, secret, c, configMap)
	}
}
