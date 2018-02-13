package main

import (
	"fmt"
	"os"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/SUSE/scf-secret-generator/secret"
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

	s := secret.GetSecretInterface()

	secrets, updates := secret.CreateSecrets(s)

	secret.GenerateSecrets(manifest, secrets, updates)

	secret.UpdateSecrets(s, secrets)
}
