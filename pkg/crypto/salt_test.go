package crypto

import (
	"testing"

	"github.com/maxlaverse/synocrypto/testdata"
	"github.com/stretchr/testify/assert"
)

func TestSaltedHashOf(t *testing.T) {
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
