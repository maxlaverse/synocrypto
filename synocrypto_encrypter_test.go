package synocrypto

import (
	"bytes"
	"io/ioutil"
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

	metadata, err := d.Metadata(bytes.NewReader(outputEncrypted.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, "67409d947d2b8ecbed8451f85ad4eead", metadata["file_md5"])
	assert.Equal(t, "md5", metadata["digest"])
}

func TestEncryptByPrivateKey(t *testing.T) {
	inputData, err := ioutil.ReadFile("testdata/random.bin")
	if !assert.NoError(t, err) {
		t.Fatal("unable to read file used for testing")
	}
	inputData = append(inputData, inputData...)
	inputData = append(inputData, inputData...)
	inputData = append(inputData, inputData...)

	optsEnc := EncrypterOptions{
		PrivateKey: []byte(testdata.FixturePrivateKey),
	}
	var outputEncrypted bytes.Buffer
	e := NewEncrypter(optsEnc)

	err = e.Encrypt(bytes.NewReader([]byte(inputData)), &outputEncrypted)
	assert.NoError(t, err)

	optsDec := DecrypterOptions{
		PrivateKey: []byte(testdata.FixturePrivateKey),
	}
	var outputDecrypted bytes.Buffer
	d := NewDecrypter(optsDec)

	err = d.Decrypt(bytes.NewReader(outputEncrypted.Bytes()), &outputDecrypted)
	assert.NoError(t, err)
	assert.Equal(t, inputData, outputDecrypted.Bytes())

	metadata, err := d.Metadata(bytes.NewReader(outputEncrypted.Bytes()))
	assert.NoError(t, err)
	assert.Equal(t, "8522d92e1a5254f60be6f0e1891d6247", metadata["file_md5"])
	assert.Equal(t, "md5", metadata["digest"])
}

func TestEncryptAndRetrieveSessionKeyByPassword(t *testing.T) {
	testCases := []struct {
		givenSalt                   string
		givenPassword               string
		givenSessionKey             []byte
		expectedSessionKeyEncrypted string
	}{
		{
			"tdJn7h4xXH",
			testdata.FixturePassword,
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"i/nx1S1Tt+EwJle82+oj2hWesTLsWSSZ/uNg8FClkl+NceHrOADQrR/G7JlSpZI/ENePKZkUR1eU0SYvFY18nW17B7Vl39+FjW8AF4CZcJo=",
		},
		{
			"0123456789",
			testdata.FixturePassword,
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"ZJWdaqdWgmf4KY8KanDwvZlC0eY5wUC8xKnRZnfLtsJcE8PrdmwYT+QLf1RI1XIj1y1/SGV5k1Ga+JSk9g8za5RQvVbGC+bpSc0S/VWP0BI=",
		},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			sessionKeyEncrypted, sessionKeyHash, err := encryptedSessionKeyByPassword(tc.givenSessionKey, tc.givenPassword, tc.givenSalt)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedSessionKeyEncrypted, string(sessionKeyEncrypted))

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
