package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	testCases := []struct {
		givenSessionKey []byte
		givenData       string
		expectedBytes   []byte
	}{
		{
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"coucou",
			[]byte{0x1e, 0x31, 0xdd, 0x53, 0xe, 0xb, 0x59, 0x6d, 0x21, 0x1d, 0xd6, 0x40, 0xad, 0x7b, 0x1c, 0x9f},
		},
		{
			[]byte{54, 67, 49, 70, 68, 52, 70, 65, 57, 53, 54, 54, 48, 52, 56, 65, 67, 69, 53, 55, 66, 69, 56, 53, 70, 67, 54, 48, 48, 69, 68, 57, 49, 52, 55, 57, 57, 70, 50, 65, 49, 65, 68, 51, 49, 50, 49, 50, 68, 54, 54, 55, 56, 68, 51, 48, 65, 67, 48, 49, 53, 68, 50, 50},
			"somethingthatismuchmorelonger",
			[]byte{0x73, 0xac, 0x6, 0x48, 0xd6, 0x30, 0x1a, 0xef, 0xbd, 0xac, 0xbe, 0x8, 0x2e, 0xba, 0x16, 0x1e, 0x82, 0x48, 0x8b, 0xa9, 0xd9, 0x53, 0x25, 0x94, 0xd6, 0x2a, 0x48, 0x72, 0xcc, 0x26, 0xe2, 0x25},
		},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			var outputEncrypted bytes.Buffer
			encrypter := NewEncrypterWithPasswordAndSalt([]byte(tc.givenSessionKey), []byte{}, &outputEncrypted)
			n, err := encrypter.Write([]byte(tc.givenData))
			assert.NoError(t, err)
			assert.Equal(t, len(tc.givenData), n)

			err = encrypter.Close()
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedBytes, outputEncrypted.Bytes())

			var outputDecrypted bytes.Buffer
			decrypter := NewDecrypterWithPasswordAndSalt([]byte(tc.givenSessionKey), []byte{}, &outputDecrypted)
			n, err = decrypter.Write(outputEncrypted.Bytes())
			assert.NoError(t, err)
			assert.Equal(t, 0, n)

			err = decrypter.Close()
			assert.NoError(t, err)
			assert.Equal(t, tc.givenData, outputDecrypted.String())
		})
	}
}
