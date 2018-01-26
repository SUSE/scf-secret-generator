package password

import (
	"testing"

	"github.com/SUSE/scf-secret-generator/util"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/core/v1"
)

func TestNewPasswordIsCreated(t *testing.T) {
	secrets := &v1.Secret{Data: map[string][]byte{}}
	updates := &v1.Secret{Data: map[string][]byte{}}

	GeneratePassword(secrets, updates, "foo")

	assert.True(t, util.IsDirty(secrets), "Secrets should be dirty after adding a password")
	assert.Len(t, secrets.Data["foo"], 64, "Generated passwords are 64 characters long")
}

func TestExistingPasswordIsNotChanged(t *testing.T) {
	data := []byte("bar")

	secrets := &v1.Secret{Data: map[string][]byte{}}
	updates := &v1.Secret{Data: map[string][]byte{}}

	secrets.Data["foo"] = data

	GeneratePassword(secrets, updates, "foo")
	assert.False(t, util.IsDirty(secrets), "Secrets should be clean because the password was not changed")
	assert.Equal(t, data, secrets.Data["foo"], "The value of existing password should not change")
}
