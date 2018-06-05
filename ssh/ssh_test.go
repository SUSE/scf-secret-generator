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

// generateKey tests

func TestNewKeyIsCreated(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}

	key := Key{
		PrivateKey:  "foo",
		Fingerprint: "bar",
	}

	err := generateKey(secrets, key)

	assert.NoError(t, err)
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

	key := Key{
		PrivateKey:  "FOO",
		Fingerprint: "BAR",
	}

	err := generateKey(secrets, key)

	assert.NoError(t, err)
	assert.Equal(t, fooData, secrets.Data["foo"])
	assert.Equal(t, barData, secrets.Data["bar"])
}

// GenerateKey tests

func TestGenerateKeys(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}

	keys := map[string]Key{
		"mysshkey": Key{
			PrivateKey:  "foo",
			Fingerprint: "bar",
		},
	}

	err := GenerateKeys(keys, secrets)

	assert.NoError(t, err)
	assert.Contains(t, string(secrets.Data["foo"]), "BEGIN RSA PRIVATE KEY")
	assert.Contains(t, string(secrets.Data["foo"]), "END RSA PRIVATE KEY")

	// 16 colon separated bytes = 47
	// 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
	assert.Len(t, secrets.Data["bar"], 47)
}

func TestMissingPrivateKey(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}

	keys := map[string]Key{
		"mysshkey": Key{
			Fingerprint: "bar",
		},
	}

	err := GenerateKeys(keys, secrets)

	assert.EqualError(t, err, "No private key name defined for SSH id `mysshkey`")
}

func TestMissingFingerprint(t *testing.T) {
	t.Parallel()

	secrets := &v1.Secret{Data: map[string][]byte{}}

	keys := map[string]Key{
		"mysshkey": Key{
			PrivateKey: "foo",
		},
	}

	err := GenerateKeys(keys, secrets)

	assert.EqualError(t, err, "No fingerprint name defined for SSH id `mysshkey`")
}

// RecordKeyInfo tests

func TestRecordingFingerprintCreatesKey(t *testing.T) {
	t.Parallel()

	keys := make(map[string]Key)

	configVar := &model.ConfigurationVariable{
		Name: "FINGERPRINT_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypeFingerprint,
	}

	RecordKeyInfo(keys, configVar)

	assert.Equal(t, "FINGERPRINT_NAME", keys["foo"].Fingerprint)
}

func TestRecordingPrivateCreatesKey(t *testing.T) {
	t.Parallel()

	keys := make(map[string]Key)

	configVar := &model.ConfigurationVariable{
		Name: "PRIVATE_KEY_NAME",
	}
	configVar.Generator = &model.ConfigurationVariableGenerator{
		ID:        "foo",
		ValueType: model.ValueTypePrivateKey,
	}

	RecordKeyInfo(keys, configVar)

	assert.Equal(t, "PRIVATE_KEY_NAME", keys["foo"].PrivateKey)
}
