package ssh

import (
	"testing"

	"github.com/SUSE/scf-secret-generator/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
)

func TestRecordKeyInfo(t *testing.T) {
	t.Parallel()

	t.Run("Fingerprint and private key are recorded", func(t *testing.T) {
		t.Parallel()

		keys := make(map[string]Key)

		configVar := &model.VariableDefinition{
			Name: "foo",
			Type: model.VariableTypeSSH,
		}

		err := RecordKeyInfo(keys, configVar)

		require.NoError(t, err)

		assert.Equal(t, "foo_FINGERPRINT", keys["foo"].Fingerprint)
		assert.Equal(t, "foo", keys["foo"].PrivateKey)
	})
}

func TestGenerateAllKeys(t *testing.T) {
	t.Parallel()

	t.Run("Generate keys", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}

		keys := map[string]Key{
			"mysshkey": Key{
				PrivateKey:  "foo",
				Fingerprint: "bar",
			},
		}

		err := GenerateAllKeys(keys, secrets)

		require.NoError(t, err)
		assert.Contains(t, string(secrets.Data["foo"]), "BEGIN RSA PRIVATE KEY")
		assert.Contains(t, string(secrets.Data["foo"]), "END RSA PRIVATE KEY")

		// 16 colon separated bytes = 47
		// 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
		assert.Len(t, secrets.Data["bar"], 47)
	})

	t.Run("Missing private key", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}

		keys := map[string]Key{
			"mysshkey": Key{
				Fingerprint: "bar",
			},
		}

		err := GenerateAllKeys(keys, secrets)

		assert.EqualError(t, err, "No private key name defined for SSH id `mysshkey`")
	})

	t.Run("Missing fingerprint", func(t *testing.T) {
		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}

		keys := map[string]Key{
			"mysshkey": Key{
				PrivateKey: "foo",
			},
		}

		err := GenerateAllKeys(keys, secrets)

		assert.EqualError(t, err, "No fingerprint name defined for SSH id `mysshkey`")
	})
}

func TestGenerateKey(t *testing.T) {
	t.Parallel()

	t.Run("New key is created", func(t *testing.T) {

		t.Parallel()

		secrets := &v1.Secret{Data: map[string][]byte{}}

		key := Key{
			PrivateKey:  "foo",
			Fingerprint: "bar",
		}

		err := generateKey(secrets, key)

		require.NoError(t, err)
		assert.Contains(t, string(secrets.Data["foo"]), "BEGIN RSA PRIVATE KEY")
		assert.Contains(t, string(secrets.Data["foo"]), "END RSA PRIVATE KEY")

		// 16 colon separated bytes = 47
		// 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
		assert.Len(t, secrets.Data["bar"], 47)
	})

	t.Run("Existing key is not changed", func(t *testing.T) {
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

		require.NoError(t, err)
		assert.Equal(t, fooData, secrets.Data["foo"])
		assert.Equal(t, barData, secrets.Data["bar"])
	})
}
