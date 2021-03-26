package crypto

import (
	"crypto/md5"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenSSLKDF(t *testing.T) {
	testCases := []struct {
		givenPasswordHex string
		givenSalt        string
		givenIteration   int
		expectedKey      string
		expectedIv       string
	}{
		// From User Password + Salt to KEY/IV to decrypt enc_key1
		// 73796E6f63727970746F = hex("synocrypt")
		{"73796E6f63727970746F", "hnEnPWyu", 1000, "29a63e045f53f7a1dbae700050bbb4a90836d1e5c42167b79efcf09015ab4eca", "0b18273c8a0231910d7f771ef33196d2"},

		// From Session Key to KEY/IV to decrypt actual data
		{"6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22", "", 1, "3cc28ecd9e7453e08bc6f75f0170884e6e22973f6341d21b00f4e1a5c313bd9d", "52d920eca9c9de82c8fcd176dad97738"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			givenPassword, err := hex.DecodeString(tc.givenPasswordHex)
			assert.NoError(t, err)

			key, iv := openSSLKDF([]byte(givenPassword), []byte(tc.givenSalt), tc.givenIteration, 32, 16, md5.New)

			assert.Equal(t, tc.expectedKey, hex.EncodeToString(key))
			assert.Equal(t, tc.expectedIv, hex.EncodeToString(iv))
		})
	}
}
