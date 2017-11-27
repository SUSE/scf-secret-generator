package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewPasswordIsCreated(t *testing.T) {
	assert := assert.New(t)

	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	result := GeneratePassword(secretData, updateData, "foo")

	assert.True(result)
	assert.Equal(len(secretData["foo"]), 64)
}

func TestExistingPasswordIsNotChanged(t *testing.T) {
	assert := assert.New(t)

	data := []byte("bar")

	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	secretData["foo"] = data

	result := GeneratePassword(secretData, updateData, "foo")
	assert.False(result)
	assert.Equal(secretData["foo"], data)
}
