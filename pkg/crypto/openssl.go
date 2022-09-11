package crypto

import (
	"crypto/aes"
	"crypto/md5"
	"hash"
)

func keyIV(password, salt []byte) ([]byte, []byte) {
	iteration := 1
	if len(salt) > 0 {
		iteration = 1000
	}

	// AES-256 is used as indicated in this "Cloud Sync White Paper":
	// https://web.archive.org/web/20160606190954/https://global.download.synology.com/download/Document/WhitePaper/Synology_Cloud_Sync_White_Paper-Based_on_DSM_6.0.pdf
	return openSSLKDF(password, salt, iteration, aes256KeySizeBytes, aes.BlockSize, md5.New)
}

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
