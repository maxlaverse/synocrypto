package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/maxlaverse/synocrypto/testdata"
	"github.com/stretchr/testify/assert"
)

func TestDecryptOnceWithPasswordAndSalt(t *testing.T) {
	testCases := []struct {
		givenPassword      string
		givenSalt          string
		givenEncryptedKey1 string
		expectedSessionKey string
	}{
		{"synocrypto", "hnEnPWyu", "0d7B6AujRw865OyzuwUKBuv9XLsdz1Cia8iUSHq//Sdn629DHgFLt5Xbb3N7+EM4cdqGx08+cJ66Ocf+bD79YIt0007iF5/+TXy1qwiHfwc=", "6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			encryptionKey1, err := base64.StdEncoding.DecodeString(tc.givenEncryptedKey1)
			assert.NoError(t, err)

			b, err := DecryptOnceWithPasswordAndSalt([]byte(tc.givenPassword), []byte(tc.givenSalt), encryptionKey1)
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedSessionKey, string(b))
		})
	}
}

func TestDecrypterPrivateKey(t *testing.T) {
	testCases := []struct {
		givenEncryptedKey2 string
		expectedSessionKey string
	}{
		{"kBbiJllccHDtABrzsCsWqqNDitS73zPywor7UG2JIausa5kWfdQ7jF9zkJfKTgPhnCRi69EM3wHs3Kl/3OoZdgftU5m/jN1tL9ou9L4kT2wRucjRMALMpJxHvEXEijrUg3qQYuJdR3OaXwrUG4HTV4mmMztLqXcY75p+TzFFg5LEwej8zXEojmbefClORp0/heoskU+UnzchU1o96MBM3BuYOlGbLGezONPe/TZmW33Tytuf4LJNEtdPviiaQ1XInJt90C7cIyCoI95jNp2DtMhQZ5r27InmbDCyZFb3gCpp6TH6zzSru361tg5ftmpmufA61BEus7ZVqKn7C2N0qg==", "6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22"},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			encryptionKey2, err := base64.StdEncoding.DecodeString(tc.givenEncryptedKey2)
			assert.NoError(t, err)

			sessionKey, err := DecryptOnceWithPrivateKey([]byte(testdata.FixturePrivateKey), encryptionKey2)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedSessionKey, string(sessionKey))
		})
	}
}

func TestPublicKeyFromPrivateKey(t *testing.T) {
	publicKey, err := PublicKeyFromPrivateKey([]byte(testdata.FixturePrivateKey))
	assert.NoError(t, err)
	assert.Equal(t, testdata.FixturePublicKey, publicKey)
}
