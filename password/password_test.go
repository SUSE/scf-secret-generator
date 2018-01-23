package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPasswordIsCreated(t *testing.T) {
	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	result := GeneratePassword(secretData, updateData, "foo")

	assert.True(t, result)
	assert.Len(t, secretData["foo"], 64)
}

func TestExistingPasswordIsNotChanged(t *testing.T) {
	data := []byte("bar")

	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	secretData["foo"] = data

	result := GeneratePassword(secretData, updateData, "foo")
	assert.False(t, result)
	assert.Equal(t, data, secretData["foo"])
}
