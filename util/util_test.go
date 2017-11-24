package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertNameToKey(t *testing.T) {
	assert := assert.New(t)

	input := "APP_PASSPHRASE"

	output := ConvertNameToKey(input)

	assert.Equal(output, "app-passphrase")
}
