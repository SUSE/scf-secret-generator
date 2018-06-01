package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SUSE/scf-secret-generator/secrets"
)

var domain = flag.String(
	"domain",
	"",
	"Domain",
)

var namespace = flag.String(
	"namespace",
	"",
	"Kubernetes namespace",
)

var serviceDomainSuffix = flag.String(
	"serviceDomainSuffix",
	"",
	"Service Domain Suffix",
)

var secretsName = flag.String(
	"secretsName",
	"",
	"Secrets Name (version string of the helm chart)",
)

var secretsGeneration = flag.String(
	"secretsGeneration",
	"",
	"Secrets Generation (rotation counter)",
)

var certExpiration = flag.Int(
	"certExpiration",
	30*365+7, // just over 30 years
	"Certificate expiration (in days)",
)

var installMode = flag.String(
	"mode",
	"",
	"Installation mode: either `install` or `upgrade`",
)

var roleManifest = flag.String(
	"roleManifest",
	"",
	"Role manifest containing definitions for all secrets to be generated",
)

func main() {
	flag.Parse()

	if *installMode != "install" && *installMode != "upgrade" {
		fmt.Fprintf(flag.CommandLine.Output(), "Invalid -mode: `%s`, must be either `install` or `upgrade`.\n", *installMode)
		flag.Usage()
		os.Exit(1)
	}

	sg := secrets.SecretGenerator{
		Domain:              *domain,
		Namespace:           *namespace,
		ServiceDomainSuffix: *serviceDomainSuffix,
		SecretsName:         *secretsName,
		SecretsGeneration:   *secretsGeneration,
		CertExpiration:      *certExpiration,
		IsInstall:           (*installMode == "install"),
	}
	if sg.Domain == "" {
		log.Fatal("-domain is not set")
	}
	if sg.Namespace == "" {
		log.Fatal("-namespace is not set")
	}
	if sg.ServiceDomainSuffix == "" {
		log.Fatal("-serviceDomainSuffix is not set")
	}
	if sg.SecretsName == "" {
		log.Fatal("-secretsName is not set")
	}
	if sg.SecretsGeneration == "" {
		log.Fatal("-secretsGeneration is not set")
	}

	file, err := os.Open(flag.Arg(0))
	if err == nil {
		err = sg.Generate(file)
	}
	if err != nil {
		log.Fatal(err)
	}
}
