package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

const (
	saltCharacterSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// IsSaltedHashOf returns true if hash is a salted hash of data
func IsSaltedHashOf(hash, data string) bool {
	return Salt(hash[:10], data) == hash
}

func Salt(salt, data string) string {
	h := md5.New()
	h.Write([]byte(salt))
	h.Write([]byte(data))
	return salt + hex.EncodeToString(h.Sum(nil))
}

func RandomSaltedHash(data string) (string, error) {
	salt, err := RandomSalt(10)
	return Salt(salt, data), err
}

func RandomSalt(size int) (string, error) {
	res := make([]byte, size)
	for i := 0; i < size; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(saltCharacterSet))))
		if err != nil {
			return "", err
		}
		res[i] = saltCharacterSet[num.Int64()]
	}
	return string(res), nil
}
