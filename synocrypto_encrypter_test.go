package synocrypto

import (
	"bytes"
	"testing"

	"github.com/maxlaverse/synocrypto/pkg/encoding"
	"github.com/maxlaverse/synocrypto/testdata"
	"github.com/stretchr/testify/assert"
)

func TestEncryptByPassword(t *testing.T) {
	inputData := "coucouc"

	optsEnc := EncrypterOptions{
		Password: testdata.FixturePassword,
	}
	var outputEncrypted bytes.Buffer
	e := NewEncrypter(optsEnc)

	err := e.Encrypt(bytes.NewReader([]byte(inputData)), &outputEncrypted)
	assert.NoError(t, err)

	optsDec := DecrypterOptions{
		Password: testdata.FixturePassword,
	}
	var outputDecrypted bytes.Buffer
	d := NewDecrypter(optsDec)

	err = d.Decrypt(bytes.NewReader(outputEncrypted.Bytes()), &outputDecrypted)
	assert.NoError(t, err)
	assert.Equal(t, inputData, outputDecrypted.String())
}

func TestEncryptAndRetrieveSessionKeyByPassword(t *testing.T) {
	testCases := []struct {
		givenSalt                   string
		givenPassword               string
		givenSessionKey             []byte
		expectedSessionKeyHash      string
		expectedSessionKeyEncrypted string
	}{
		{
			"tdJn7h4xXH",
			testdata.FixturePassword,
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"tdJn7h4xXHee4692313a3d1d425d1afe95bcdbcc73",
			"i/nx1S1Tt+EwJle82+oj2hWesTLsWSSZ/uNg8FClkl+NceHrOADQrR/G7JlSpZI/ENePKZkUR1eU0SYvFY18nW17B7Vl39+FjW8AF4CZcJo=",
		},
		{
			"0123456789",
			testdata.FixturePassword,
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"012345678900c30a6ddf92c5885856387b6111c0d2",
			"ZJWdaqdWgmf4KY8KanDwvZlC0eY5wUC8xKnRZnfLtsJcE8PrdmwYT+QLf1RI1XIj1y1/SGV5k1Ga+JSk9g8za5RQvVbGC+bpSc0S/VWP0BI=",
		},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			sessionKeyEncrypted, sessionKeyHash, err := encryptedSessionKeyByPassword(tc.givenSessionKey, tc.givenPassword, tc.givenSalt)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedSessionKeyEncrypted, string(sessionKeyEncrypted))
			assert.Equal(t, tc.expectedSessionKeyHash, string(sessionKeyHash))

			metadata := map[string]interface{}{}
			metadata[encoding.MetadataFieldSalt] = tc.givenSalt
			metadata[encoding.MetadataFieldVersion] = map[string]interface{}{"minor": 0, "major": 1}
			metadata[encoding.MetadataFieldEncryptionKey1] = sessionKeyEncrypted
			metadata[encoding.MetadataFieldEncryptionKey1Hash] = sessionKeyHash

			sessionKeyDec, err := retrieveSessionKeyByPassword(tc.givenPassword, metadata)
			assert.NoError(t, err)
			assert.Equal(t, tc.givenSessionKey, sessionKeyDec)
		})
	}
}
