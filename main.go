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
	"Secrets Name",
)

var secretsGeneration = flag.String(
	"secretsGeneration",
	"",
	"Secrets Generation",
)

var certExpiration = flag.Int(
	"certExpiration",
	10950, // 30 years * 365 days
	"Certificate expiration (in days)",
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Printf("Usage: %s <role-manifest>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	sg := secrets.SecretGenerator{
		Domain:              *domain,
		Namespace:           *namespace,
		ServiceDomainSuffix: *serviceDomainSuffix,
		SecretsName:         *secretsName,
		SecretsGeneration:   *secretsGeneration,
		CertExpiration:      *certExpiration,
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
