package password

import (
	"github.com/SUSE/scf-secret-generator/util"
	"github.com/dchest/uniuri"
)

// GeneratePassword generates a password for `secretName` if it doesn't already exist
func GeneratePassword(secretData map[string][]byte, updateData map[string][]byte, secretName string) bool {
	secretKey := util.ConvertNameToKey(secretName)

	// Only create keys, don't update them
	if len(secretData[secretKey]) > 0 {
		return false
	}

	if len(updateData[secretKey]) > 0 {
		secretData[secretKey] = updateData[secretKey]
	} else {
		password := uniuri.NewLen(64)
		secretData[secretKey] = []byte(password)
	}
	return true
}
