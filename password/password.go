package password

import (
	"strings"

	"github.com/dchest/uniuri"
)

// GeneratePassword generates a password for `secretName` if it doesn't already exist
func GeneratePassword(secretData map[string][]byte, secretName string) bool {
	secretKey := strings.Replace(strings.ToLower(secretName), "_", "-", -1)

	// Only create keys, don't update them
	if _, ok := secretData[secretKey]; !ok {
		password := uniuri.NewLen(64)
		secretData[secretKey] = []byte(password)
		return true
	}

	return false
}
