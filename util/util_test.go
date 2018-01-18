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
	t.Parallel()

	assert := assert.New(t)

	input := "APP_PASSPHRASE"

	output := ConvertNameToKey(input)

	assert.Equal("app-passphrase", output)
}

func TestSetupEnv(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	osEnviron = func() []string {
		return []string{"FOO=BAR"}
	}

	setupEnv()

	assert.Equal("BAR", env["FOO"])
}

func TestExpandEnvTemplates(t *testing.T) {
	assert := assert.New(t)

	//
	// Test that variable replacement works
	//
	t.Run("VariableReplacementShouldWork", func(t *testing.T) {
		t.Parallel()
		env["FOO"] = "BAR"
		assert.Equal("a BAR variable", ExpandEnvTemplates("a {{.FOO}} variable"))
	})

	//
	// Test that malformed templates fail
	//
	t.Run("MalformedTemplatesShouldFail", func(t *testing.T) {
		t.Parallel()

		origLogFatalf := logFatalf
		defer func() {
			logFatalf = origLogFatalf
		}()

		var mockLog MockLog
		logFatalf = mockLog.Fatal

		mockLog.On("Fatal",
			"Can't parse templates in '%s': %s",
			[]interface{}{"{{.bad", errors.New("template: :1: unclosed action")})
		ExpandEnvTemplates("{{.bad")
		mockLog.AssertCalled(t, "Fatal",
			"Can't parse templates in '%s': %s",
			[]interface{}{"{{.bad", errors.New("template: :1: unclosed action")})
	})
}
