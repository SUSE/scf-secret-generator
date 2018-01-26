package util

import (
	"bytes"
	"log"
	"os"
	"strings"
	"text/template"

	"k8s.io/api/core/v1"
)

// Key used to show that the secrets have been modified
const DIRTY_SECRET = "this-secret-is-dirty"

var env map[string]string

var osEnviron = os.Environ
var logFatalf = log.Fatalf

func init() {
	setupEnv()
}

func setupEnv() {
	env = make(map[string]string)
	for _, e := range osEnviron() {
		pair := strings.SplitN(e, "=", 2)
		env[pair[0]] = pair[1]
	}
}

func ConvertNameToKey(name string) string {
	return strings.Replace(strings.ToLower(name), "_", "-", -1)
}

func ExpandEnvTemplates(str string) string {
	t, err := template.New("").Parse(str)
	if err != nil {
		logFatalf("Can't parse templates in '%s': %s", str, err)
		return ""
	}
	buf := &bytes.Buffer{}
	t.Execute(buf, env)
	return buf.String()
}

func IsDirty(secrets *v1.Secret) bool {
	_, exists := secrets.Data[DIRTY_SECRET]
	return exists
}

func MarkAsClean(secrets *v1.Secret) {
	delete(secrets.Data, DIRTY_SECRET)
}

func MarkAsDirty(secrets *v1.Secret) {
	secrets.Data[DIRTY_SECRET] = []byte("")
}
