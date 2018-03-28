package main

import (
	"fmt"
	"log"
	"os"

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

	sg := secrets.SecretGenerator{
		Namespace:           os.Getenv("KUBERNETES_NAMESPACE"),
		ServiceDomainSuffix: os.Getenv("KUBE_SERVICE_DOMAIN_SUFFIX"),
		SecretsName:         os.Getenv("KUBE_SECRETS_GENERATION_NAME"),
		SecretsGeneration:   os.Getenv("KUBE_SECRETS_GENERATION_COUNTER"),
	}
	// XXX All these settings should be passed from the commandline and not the environment
	if sg.Namespace == "" {
		log.Fatal("KUBERNETES_NAMESPACE is not set")
	}
	if sg.ServiceDomainSuffix == "" {
		log.Fatal("KUBE_SERVICE_DOMAIN_SUFFIX is not set")
	}
	if sg.SecretsName == "" {
		log.Fatal("KUBE_SECRETS_GENERATION_NAME is not set")
	}
	if sg.SecretsGeneration == "" {
		log.Fatal("KUBE_SECRETS_GENERATION_COUNTER is not set")
	}

	file, err := os.Open(os.Args[1])
	if err == nil {
		err = sg.Generate(file)
	}
	if err != nil {
		log.Fatal(err)
	}
}
