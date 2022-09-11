package crypto

import (
	"fmt"
)

// From  https://golang-examples.tumblr.com/post/98350728789/pkcs-7-padding

// Returns slice of the original data without padding.
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding (padlen: %d, blocklen: %d)", padlen, blocklen)
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding (padlen: %d, pad: %d)", padlen, pad)
		}
	}

	return data[:len(data)-padlen], nil
}
