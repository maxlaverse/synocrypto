package synocrypto

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/maxlaverse/synocrypto/pkg/crypto"
	"github.com/maxlaverse/synocrypto/pkg/encoding"
)

const (
	saltCharacterSet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

type encrypter struct {
	options EncrypterOptions
}

func (e *encrypter) Encrypt(in io.Reader, out io.Writer) error {
	if e.options.UseCompression {
		return fmt.Errorf("compression is not supported yet")
	}

	salt, err := randomSalt()
	if err != nil {
		return fmt.Errorf("unable to generate random salt: %w", err)
	}

	sessionKey, err := randomSessionKey()
	if err != nil {
		return fmt.Errorf("unable to generate random session key: %w", err)
	}

	sessionKeyHex := bytesToHex(sessionKey)
	passwordEncryptedSessionKey, passwordEncryptedSessionKeyHash, err := encryptedSessionKeyByPassword(sessionKeyHex, e.options.Password, salt)
	if err != nil {
		return fmt.Errorf("error generating password encrypted key: %w", err)
	}

	metadata := map[string]interface{}{}
	metadata[encoding.MetadataFieldCompress] = 0
	metadata[encoding.MetadataFieldEncrypt] = 1
	metadata[encoding.MetadataFieldSalt] = salt
	metadata[encoding.MetadataFieldVersion] = map[string]interface{}{"major": 1, "minor": 0}
	metadata[encoding.MetadataFieldSessionKeyHash] = crypto.SaltedHashOf(salt, string(sessionKeyHex))
	metadata[encoding.MetadataFieldEncryptionKey1] = passwordEncryptedSessionKey
	metadata[encoding.MetadataFieldEncryptionKey1Hash] = passwordEncryptedSessionKeyHash
	if e.options.Filename != "" {
		metadata[encoding.MetadataFieldFilename] = e.options.Filename
	}
	if !e.options.DisableDigestGeneration {
		metadata[encoding.MetadataFieldDigest] = "md5"
	}

	objWriter := encoding.NewWriter(out)
	err = objWriter.WriteMetadata(metadata)
	if err != nil {
		return fmt.Errorf("error writing metadata: %w", err)
	}

	cryptoOut := crypto.NewEncrypterWithPasswordAndSalt(sessionKey, []byte{}, objWriter)

	copyDst := cryptoOut.(io.Writer)
	var hasher hash.Hash
	if !e.options.DisableDigestGeneration {
		hasher = md5.New()
		copyDst = io.MultiWriter(hasher, copyDst)
	}
	_, err = io.Copy(copyDst, in)
	if err != nil {
		return fmt.Errorf("error copying data: %w", err)
	}

	if hasher != nil {
		actualFileDigest := hex.EncodeToString(hasher.Sum(nil))
		err = objWriter.WriteMetadata(map[string]interface{}{
			encoding.MetadataFieldMd5Digest: actualFileDigest,
		})
		if err != nil {
			return fmt.Errorf("error writing digest: %w", err)
		}
	}
	return cryptoOut.Close()
}

func encryptedSessionKeyByPassword(sessionKey []byte, password, salt string) (string, string, error) {
	encryptedBytes, err := crypto.EncryptOnceWithPasswordAndSalt([]byte(password), []byte(salt), sessionKey)
	if err != nil {
		return "", "", err
	}

	encrypted := base64.StdEncoding.EncodeToString(encryptedBytes)
	return encrypted, crypto.SaltedHashOf(salt, password), nil
}

func bytesToHex(str []byte) []byte {
	data := make([]byte, hex.EncodedLen(len(str)))
	hex.Encode(data, []byte(str))
	return data
}

func randomSalt() (string, error) {
	res := make([]byte, 10)
	for i := 0; i < 10; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(saltCharacterSet))))
		if err != nil {
			return "", err
		}
		res[i] = saltCharacterSet[num.Int64()]
	}
	return string(res), nil
}

func randomSessionKey() ([]byte, error) {
	res := make([]byte, 32)
	for i := 0; i < 32; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(256)))
		if err != nil {
			return nil, err
		}
		res[i] = byte(num.Int64())
	}
	return res, nil
}
