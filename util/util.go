package util

import "strings"

func ConvertNameToKey(name string) string {
	return strings.Replace(strings.ToLower(name), "_", "-", -1)
}
