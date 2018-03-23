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

	sg := secrets.NewSecretGenerator()
	manifest := model.GetManifest(os.Args[1])
	sg.Generate(manifest)
}
