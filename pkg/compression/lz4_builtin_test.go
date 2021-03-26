package compression

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecompressingFiles(t *testing.T) {
	testCases := []struct {
		filepath string
	}{
		{"../../testdata/Mark.Twain-Tom.Sawyer.txt"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			inputData, err := ioutil.ReadFile(fmt.Sprintf("%s.lz4", tc.filepath))
			if !assert.NoError(t, err) {
				t.Fatal("unable to read file used for testing")
			}

			expectedOutputData, err := ioutil.ReadFile(tc.filepath)
			if !assert.NoError(t, err) {
				t.Fatal("unable to read file used for testing")
			}

			var b bytes.Buffer
			z, err := NewLz4Builtin(&b)

			assert.NoError(t, err)

			_, err = z.Write(inputData)
			assert.NoError(t, err)

			err = z.Close()
			assert.NoError(t, err)

			assert.Equal(t, expectedOutputData, b.Bytes())
		})
	}
}
