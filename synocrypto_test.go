package synocrypto

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/maxlaverse/synocrypto/testdata"
	"github.com/stretchr/testify/assert"
)

func TestDecryptingFiles(t *testing.T) {
	testCases := []struct {
		givenFilepath    string
		givenPassword    string
		givenPrivateKey  string
		expectedMetadata string
	}{
		{"testdata/Mark.Twain-Tom.Sawyer.txt", testdata.FixturePassword, "", "24bde34ecb5632ac6637325e8a334a9c"},
		{"testdata/Mark.Twain-Tom.Sawyer.txt", "", testdata.FixturePrivateKey, "24bde34ecb5632ac6637325e8a334a9c"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			inputData, err := ioutil.ReadFile(fmt.Sprintf("%s.enc", tc.givenFilepath))
			if !assert.NoError(t, err) {
				t.Fatal("unable to read file used for testing")
			}

			expectedOutputData, err := ioutil.ReadFile(tc.givenFilepath)
			if !assert.NoError(t, err) {
				t.Fatal("unable to read file used for testing")
			}

			opts := DecrypterOptions{
				Password:   tc.givenPassword,
				PrivateKey: []byte(tc.givenPrivateKey),
			}
			var outputDecrypted bytes.Buffer
			d := NewDecrypter(opts)

			err = d.Decrypt(bytes.NewReader(inputData), &outputDecrypted)
			assert.NoError(t, err)
			assert.Equal(t, expectedOutputData, outputDecrypted.Bytes())

			metadata, err := d.Metadata(bytes.NewReader(inputData))
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedMetadata, metadata["file_md5"])
		})
	}
}
