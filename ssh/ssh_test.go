package ssh

// create a key if not found
// update key if found
// how to test generating the keys?

import (
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/core/v1"
)

// GenerateSSHKey tests

func TestNewKeyIsCreated(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}

	key := SSHKey{
		PrivateKey:  "foo",
		Fingerprint: "bar",
	}

	GenerateSSHKey(secrets, key)

	assert.Contains(t, string(secrets.Data["foo"]), "BEGIN RSA PRIVATE KEY")
	assert.Contains(t, string(secrets.Data["foo"]), "END RSA PRIVATE KEY")

	// 16 colon separated bytes = 47
	// 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
	assert.Len(t, secrets.Data["bar"], 47)
}

func TestExistingKeyIsNotChanged(t *testing.T) {
	t.Parallel()

	fooData := []byte("foo-data")
	barData := []byte("bar-data")

	secrets := &v1.Secret{Data: map[string][]byte{}}

	// Also tests for FOO / foo case conversion
	secrets.Data["foo"] = fooData
	secrets.Data["bar"] = barData

	key := SSHKey{
		PrivateKey:  "FOO",
		Fingerprint: "BAR",
	}

	GenerateSSHKey(secrets, key)
	assert.Equal(t, fooData, secrets.Data["foo"])
	assert.Equal(t, barData, secrets.Data["bar"])
}

// RecordSSHKeyInfo tests

func TestRecordingFingerprintCreatesKey(t *testing.T) {
	t.Parallel()

	keys := make(map[string]SSHKey)

	configVar := &model.ConfigurationVariable{
		Name: "FINGERPRINT_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypeFingerprint,
	}

	RecordSSHKeyInfo(keys, configVar)

	assert.Equal(t, "FINGERPRINT_NAME", keys["foo"].Fingerprint)
}

func TestRecordingPrivateCreatesKey(t *testing.T) {
	t.Parallel()

	keys := make(map[string]SSHKey)

	configVar := &model.ConfigurationVariable{
		Name: "PRIVATE_KEY_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypePrivateKey,
	}

	RecordSSHKeyInfo(keys, configVar)

	assert.Equal(t, "PRIVATE_KEY_NAME", keys["foo"].PrivateKey)
}
