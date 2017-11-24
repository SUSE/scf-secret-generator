package password

import (
	"github.com/SUSE/scf-secret-generator/util"
	"github.com/dchest/uniuri"
)

// GeneratePassword generates a password for `secretName` if it doesn't already exist
func GeneratePassword(secretData map[string][]byte, secretName string) bool {
	secretKey := util.ConvertNameToKey(secretName)

	// Only create keys, don't update them
	if _, ok := secretData[secretKey]; ok {
		return false
	}

	password := uniuri.NewLen(64)
	secretData[secretKey] = []byte(password)
	return true
}
