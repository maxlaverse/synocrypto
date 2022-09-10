package crypto

import (
	"hash"
)

func openSSLKDF(password, salt []byte, iter, keyLen, ivLen int, h func() hash.Hash) ([]byte, []byte) {
	hasher := h()
	derivedKey := make([]byte, 0, (keyLen+ivLen)/hasher.Size()*hasher.Size())

	lastHashedSum := []byte{}
	for len(derivedKey) < keyLen+ivLen {
		hasher.Write(lastHashedSum)
		hasher.Write(password)
		hasher.Write(salt)
		lastHashedSum = hasher.Sum(nil)
		hasher.Reset()

		for i := 1; i < iter; i++ {
			hasher.Write(lastHashedSum)
			lastHashedSum = hasher.Sum(nil)
			hasher.Reset()
		}

		derivedKey = append(derivedKey, lastHashedSum...)
	}
	return derivedKey[0:keyLen], derivedKey[keyLen : keyLen+ivLen]
}
