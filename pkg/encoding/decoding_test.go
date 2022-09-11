package encoding

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCaseString = []struct {
	encoded string
	decoded string
}{
	{"\x00\x03\x6d\x64\x35", "md5"},
	{"\x00\x19\x4d\x61\x72\x6b\x2e\x54\x77\x61\x69\x6e\x2d\x54\x6f\x6d\x2e\x53\x61\x77\x79\x65\x72\x2e\x74\x78\x74", "Mark.Twain-Tom.Sawyer.txt"},
	{"\x00\x2a\x74\x64\x4a\x6e\x37\x68\x34\x78\x58\x48\x65\x65\x34\x36\x39\x32\x33\x31\x33\x61\x33\x64\x31\x64\x34\x32\x35\x64\x31\x61\x66\x65\x39\x35\x62\x63\x64\x62\x63\x63\x37\x33", "tdJn7h4xXHee4692313a3d1d425d1afe95bcdbcc73"},
	{"\x00\x00", ""},
}

var testCaseDict = []struct {
	encoded string
	decoded map[string]interface{}
}{
	{"\x10\x00\x05\x6d\x61\x6a\x6f\x72\x01\x01\x03\x10\x00\x05\x6d\x69\x6e\x6f\x72\x01\x01\x01\x40", map[string]interface{}{"major": 3, "minor": 1}},
}

var testCaseInt = []struct {
	encoded string
	decoded int
}{
	{"\x01\x00", 0},
	{"\x01\x03", 3},
	{"\x01\x9b", 155},
	{"\x02\x12\x34", 4660},
}

func TestReadString(t *testing.T) {
	for _, tc := range testCaseString {
		t.Run("", func(t *testing.T) {
			r := bytes.NewReader([]byte(tc.encoded))
			s, err := readString(r)

			assert.NoError(t, err)
			assert.Equal(t, tc.decoded, s)
		})
	}
}

func TestReadDict(t *testing.T) {
	for _, tc := range testCaseDict {
		t.Run("", func(t *testing.T) {
			r := bytes.NewReader([]byte(tc.encoded))
			m, err := readDict(r)

			assert.NoError(t, err)
			assert.Equal(t, tc.decoded, m)
		})
	}
}

func TestReadInt(t *testing.T) {
	for _, tc := range testCaseInt {
		t.Run("", func(t *testing.T) {
			r := bytes.NewReader([]byte(tc.encoded))
			i, err := readInt(r)

			assert.NoError(t, err)
			assert.Equal(t, tc.decoded, i)
		})
	}
}
