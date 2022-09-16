package crypto

import (
	"testing"

	"github.com/maxlaverse/synocrypto/testdata"
	"github.com/stretchr/testify/assert"
)

func TestIsSaltedHashOf(t *testing.T) {
	testCases := []struct {
		givenSessionKey        string
		expectedSessionKeyHash string
	}{
		{"6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22", "ZEoJGjyTnBed4d99ebd929c9ff24194bc00355457c"},
		{"synocrypto", "tdJn7h4xXHee4692313a3d1d425d1afe95bcdbcc73"},
		{"synocrypto", "fhJOMktud433f9d8b06280d5b001ce644790436b0d"},
		{testdata.FixturePublicKey, "nqDf9Q66ULbe5c5005e0c4c8fb7db1f5d49099a40c"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			assert.True(t, IsSaltedHashOf(tc.expectedSessionKeyHash, tc.givenSessionKey))
		})
	}
}

func TestSalt(t *testing.T) {
	testCases := []struct {
		salt       string
		saltedHash string
		value      string
	}{
		{"tdJn7h4xXH", "tdJn7h4xXHee4692313a3d1d425d1afe95bcdbcc73", "synocrypto"},
		{"0123456789", "012345678900c30a6ddf92c5885856387b6111c0d2", "synocrypto"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			salted := Salt(tc.salt, tc.value)
			assert.Equal(t, tc.saltedHash, salted)

			// Extra verification
			assert.True(t, IsSaltedHashOf(salted, tc.value))
		})
	}
}
