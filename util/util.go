package util

import (
	"bytes"
	"log"
	"os"
	"strings"
	"text/template"
)

var env map[string]string
var override map[string]string

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
	override = make(map[string]string)
}

// OverrideEnv adds an environment override for testing purposes
func OverrideEnv(key, value string) {
	override[key] = value
}

// ClearOverrides removes any existing overridden environment variables
func ClearOverrides() {
	override = make(map[string]string)
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
	mapping := make(map[string]string)
	for k, v := range env {
		mapping[k] = v
	}
	for k, v := range override {
		mapping[k] = v
	}
	t.Execute(buf, mapping)
	return buf.String()
}
