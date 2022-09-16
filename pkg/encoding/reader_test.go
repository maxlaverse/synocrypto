package encoding

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataExtraction(t *testing.T) {
	expectedMetadata := map[string]interface{}{
		"compress":         1,
		"digest":           "md5",
		"enc_key1":         "0d7B6AujRw865OyzuwUKBuv9XLsdz1Cia8iUSHq//Sdn629DHgFLt5Xbb3N7+EM4cdqGx08+cJ66Ocf+bD79YIt0007iF5/+TXy1qwiHfwc=",
		"enc_key2":         "kBbiJllccHDtABrzsCsWqqNDitS73zPywor7UG2JIausa5kWfdQ7jF9zkJfKTgPhnCRi69EM3wHs3Kl/3OoZdgftU5m/jN1tL9ou9L4kT2wRucjRMALMpJxHvEXEijrUg3qQYuJdR3OaXwrUG4HTV4mmMztLqXcY75p+TzFFg5LEwej8zXEojmbefClORp0/heoskU+UnzchU1o96MBM3BuYOlGbLGezONPe/TZmW33Tytuf4LJNEtdPviiaQ1XInJt90C7cIyCoI95jNp2DtMhQZ5r27InmbDCyZFb3gCpp6TH6zzSru361tg5ftmpmufA61BEus7ZVqKn7C2N0qg==",
		"encrypt":          1,
		"file_name":        "Mark.Twain-Tom.Sawyer.txt",
		"key1_hash":        "tdJn7h4xXHee4692313a3d1d425d1afe95bcdbcc73",
		"key2_hash":        "nqDf9Q66ULbe5c5005e0c4c8fb7db1f5d49099a40c",
		"salt":             "hnEnPWyu",
		"session_key_hash": "ZEoJGjyTnBed4d99ebd929c9ff24194bc00355457c",
		"version": map[string]interface{}{
			"major": 3,
			"minor": 1,
		},
	}

	data, err := ioutil.ReadFile("../../testdata/Mark.Twain-Tom.Sawyer.txt.enc")
	if !assert.NoError(t, err) {
		t.Fatal("unable to read file used for testing")
	}

	reader := NewReader(bytes.NewReader(data))
	d, err := reader.DataChannel()
	assert.NoError(t, err)
	emptyChannel(d)

	assert.Equal(t, expectedMetadata, reader.Metadata())
}

func TestVerifyingValidCloudSyncHeader(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("__CLOUDSYNC_ENC__d8d6ba7b9df02ef39a33ef912a91dc56")
	err := verifyCloudSyncHeader(&b)

	assert.NoError(t, err)
}

func TestVerifyingInvalidCloudSyncHeader(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("__CLOUDSYNC_ENC__d8d6ba7b9df3ef912a91dc56")
	err := verifyCloudSyncHeader(&b)

	assert.Error(t, err)
}

func emptyChannel(d chan []byte) {
	for {
		select {
		case <-d:
		default:
			return
		}
	}
}
