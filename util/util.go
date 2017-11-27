package util

import (
	"bytes"
	"log"
	"os"
	"strings"
	"text/template"
)

var env map[string]string

func init() {
	env = make(map[string]string)
	for _, e := range os.Environ() {
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
		log.Fatalf("Can't parse templates in '%s': %s", str, err)
	}
	buf := &bytes.Buffer{}
	t.Execute(buf, env)
	return buf.String()
}
