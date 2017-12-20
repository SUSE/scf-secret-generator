package util

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockLog struct {
	mock.Mock
}

func (m *MockLog) Fatal(str string, message ...interface{}) {
	m.Called(str, message)
}

func TestConvertNameToKey(t *testing.T) {
	assert := assert.New(t)

	input := "APP_PASSPHRASE"

	output := ConvertNameToKey(input)

	assert.Equal(output, "app-passphrase")
}

func TestSetupEnv(t *testing.T) {
	assert := assert.New(t)

	osEnviron = func() []string {
		return []string{"FOO=BAR"}
	}

	setupEnv()

	assert.Equal(env["FOO"], "BAR")
}

func TestExpandEnvTemplates(t *testing.T) {
	assert := assert.New(t)

	origLogFatalf := logFatalf
	defer func() {
		logFatalf = origLogFatalf
	}()

	var mockLog MockLog
	logFatalf = mockLog.Fatal

	//
	// Test that variable replacement works
	//
	env["FOO"] = "BAR"
	assert.Equal(ExpandEnvTemplates("a {{.FOO}} variable"), "a BAR variable")

	//
	// Test that malformed templates fail
	//
	mockLog.On("Fatal",
		"Can't parse templates in '%s': %s",
		[]interface{}{"{{.bad", errors.New("template: :1: unclosed action")})
	ExpandEnvTemplates("{{.bad")
	mockLog.AssertCalled(t, "Fatal",
		"Can't parse templates in '%s': %s",
		[]interface{}{"{{.bad", errors.New("template: :1: unclosed action")})
}
