package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/SUSE/scf-secret-generator/secrets"
)

var certExpiration = flag.Int(
	"certExpiration",
	30*365+7, // just over 30 years
	"Certificate expiration (in days)",
)

var clusterDomain = flag.String(
	"clusterDomain",
	"cluster.local",
	"Kubernetes cluster domain, normally cluster.local",
)

var domain = flag.String(
	"domain",
	"",
	"Domain",
)

var installMode = flag.String(
	"mode",
	"",
	"Installation mode: either `install` or `upgrade`",
)

var namespace = flag.String(
	"namespace",
	"",
	"Kubernetes namespace",
)

var roleManifest = flag.String(
	"roleManifest",
	"",
	"Role manifest containing definitions for all secrets to be generated",
)

var secretsGeneration = flag.String(
	"secretsGeneration",
	"",
	"Secrets Generation (rotation counter)",
)

var secretsName = flag.String(
	"secretsName",
	"",
	"Secrets Name (version string of the helm chart)",
)

type envSettings map[string]string

var templateEnv = make(envSettings)

func (env *envSettings) String() string {
	return ""
}

func (env *envSettings) Set(value string) error {
	s := strings.SplitN(value, "=", 2)
	if len(s) == 2 {
		(*env)[s[0]] = s[1]
	} else {
		(*env)[s[0]] = ""
	}
	return nil
}

func main() {
	flag.Var(&templateEnv, "set", "Define config variable for template expansion.")
	flag.Parse()

	if *installMode != "install" && *installMode != "upgrade" {
		fmt.Fprintf(flag.CommandLine.Output(), "Invalid -mode: `%s`, must be either `install` or `upgrade`.\n", *installMode)
		flag.Usage()
		os.Exit(1)
	}

	sg := secrets.SecretGenerator{
		CertExpiration:    *certExpiration,
		ClusterDomain:     *clusterDomain,
		Domain:            *domain,
		IsInstall:         (*installMode == "install"),
		Namespace:         *namespace,
		SecretsGeneration: *secretsGeneration,
		SecretsName:       *secretsName,
		TemplateEnv:       templateEnv,
	}
	if sg.Domain == "" {
		log.Fatal("-domain is not set")
	}
	if sg.Namespace == "" {
		log.Fatal("-namespace is not set")
	}
	if sg.SecretsGeneration == "" {
		log.Fatal("-secretsGeneration is not set")
	}
	if sg.SecretsName == "" {
		log.Fatal("-secretsName is not set")
	}

	sg.TemplateEnv["DOMAIN"] = sg.Domain
	sg.TemplateEnv["KUBERNETES_CLUSTER_DOMAIN"] = sg.ClusterDomain
	sg.TemplateEnv["KUBERNETES_NAMESPACE"] = sg.Namespace

	file, err := os.Open(flag.Arg(0))
	if err == nil {
		err = sg.Generate(file)
	}
	if err != nil {
		log.Fatal(err)
	}
}
