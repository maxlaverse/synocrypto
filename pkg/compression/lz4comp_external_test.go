package compression

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func skipCI(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping testing in CI environment")
	}
}

func TestCompressingExternalFileWorks(t *testing.T) {
	skipCI(t)
	testCases := []struct {
		filepath string
	}{
		{"../../testdata/Mark.Twain-Tom.Sawyer.txt"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			inputData, err := ioutil.ReadFile(tc.filepath)
			if !assert.NoError(t, err) {
				t.Fatal("unable to read file used for testing")
			}

			z, err := NewLz4CompExternal(bytes.NewReader(inputData))
			assert.NoError(t, err)

			res, err := ioutil.ReadAll(z)
			assert.NoError(t, err)

			var b bytes.Buffer
			z2, err := NewLz4DecompBuiltin(&b)
			assert.NoError(t, err)

			_, err = z2.Write(res)
			assert.NoError(t, err)

			err = z2.Close()
			assert.NoError(t, err)

			assert.Equal(t, inputData, b.Bytes())
		})
	}
}
