package encoding

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteString(t *testing.T) {
	for _, tc := range testCaseString {
		t.Run("", func(t *testing.T) {
			var outputEncrypted bytes.Buffer
			err := writeString(tc.decoded, &outputEncrypted)

			assert.NoError(t, err)
			assert.Equal(t, tc.encoded, outputEncrypted.String())
		})
	}
}

func TestWriteDict(t *testing.T) {
	for _, tc := range testCaseDict {
		t.Run("", func(t *testing.T) {
			var outputEncrypted bytes.Buffer
			err := writeDict(tc.decoded, &outputEncrypted)

			assert.NoError(t, err)
			assert.Equal(t, []byte(tc.encoded), outputEncrypted.Bytes())
		})
	}
}

func TestWriteInt(t *testing.T) {
	for _, tc := range testCaseInt {
		t.Run("", func(t *testing.T) {
			var outputEncrypted bytes.Buffer
			err := writeInt(tc.decoded, &outputEncrypted)

			assert.NoError(t, err)
			assert.Equal(t, tc.encoded, outputEncrypted.String())
		})
	}
}
