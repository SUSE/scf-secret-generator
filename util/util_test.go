package util

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"k8s.io/api/core/v1"
)

type MockLog struct {
	mock.Mock
}

func (m *MockLog) Fatal(str string, message ...interface{}) {
	m.Called(str, message)
}

func TestConvertNameToKey(t *testing.T) {
	t.Parallel()

	input := "APP_PASSPHRASE"

	output := ConvertNameToKey(input)

	assert.Equal(t, "app-passphrase", output)
}

func TestSetupEnv(t *testing.T) {
	t.Parallel()

	osEnviron = func() []string {
		return []string{"FOO=BAR"}
	}

	setupEnv()

	assert.Equal(t, "BAR", env["FOO"])
}

func TestExpandEnvTemplates(t *testing.T) {
	//
	// Test that variable replacement works
	//
	t.Run("VariableReplacementShouldWork", func(t *testing.T) {
		t.Parallel()
		env["FOO"] = "BAR"
		assert.Equal(t, "a BAR variable", ExpandEnvTemplates("a {{.FOO}} variable"))
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

func TestDirtySecrets(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}
	assert.False(t, IsDirty(secrets))

	MarkAsClean(secrets)
	assert.False(t, IsDirty(secrets))

	MarkAsDirty(secrets)
	assert.True(t, IsDirty(secrets))

	MarkAsClean(secrets)
	assert.False(t, IsDirty(secrets))
}
