package crypto

import (
	"crypto/md5"
	"encoding/hex"
)

// IsSaltedHashOf returns true if hash is a salted hash of data
func IsSaltedHashOf(hash, data string) bool {
	return SaltedHashOf(hash[:10], data) == hash
}

func SaltedHashOf(salt, data string) string {
	h := md5.New()
	h.Write([]byte(salt))
	h.Write([]byte(data))
	return salt + hex.EncodeToString(h.Sum(nil))
}
