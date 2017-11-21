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

	s := secret.GetSecrets()

	create, secrets := secret.GetOrCreateSecret(s)

	dirty := secret.GenerateSecrets(manifest, secrets)

	secret.UpdateSecrets(s, secrets, create, dirty)
}
