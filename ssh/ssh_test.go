package ssh

// create a key if not found
// update key if found
// how to test generating the keys?

import (
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/stretchr/testify/assert"
)

// GenerateSSHKey tests

func TestNewKeyIsCreated(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)
	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	key := SSHKey{
		PrivateKey:  "foo",
		Fingerprint: "bar",
	}

	result := GenerateSSHKey(secretData, updateData, key)

	assert.True(result)

	assert.Contains(string(secretData["foo"]), "BEGIN RSA PRIVATE KEY")
	assert.Contains(string(secretData["foo"]), "END RSA PRIVATE KEY")

	// 16 colon separated bytes = 47
	// 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
	assert.Len(secretData["bar"], 47)
}

func TestExistingKeyIsNotChanged(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	fooData := []byte("foo-data")
	barData := []byte("bar-data")

	secretData := make(map[string][]byte)
	updateData := make(map[string][]byte)

	// Also tests for FOO / foo case conversion
	secretData["foo"] = fooData
	secretData["bar"] = barData

	key := SSHKey{
		PrivateKey:  "FOO",
		Fingerprint: "BAR",
	}

	result := GenerateSSHKey(secretData, updateData, key)
	assert.False(result)
	assert.Equal(fooData, secretData["foo"])
	assert.Equal(barData, secretData["bar"])
}

// RecordSSHKeyInfo tests

func TestRecordingFingerprintCreatesKey(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	keys := make(map[string]SSHKey)

	configVar := model.ConfigurationVariable{
		Name: "FINGERPRINT_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypeFingerprint,
	}

	RecordSSHKeyInfo(keys, &configVar)

	assert.Equal("FINGERPRINT_NAME", keys["foo"].Fingerprint)
}

func TestRecordingPrivateCreatesKey(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	keys := make(map[string]SSHKey)

	configVar := model.ConfigurationVariable{
		Name: "PRIVATE_KEY_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypePrivateKey,
	}

	RecordSSHKeyInfo(keys, &configVar)

	assert.Equal("PRIVATE_KEY_NAME", keys["foo"].PrivateKey)
}
