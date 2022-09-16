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
	"path"

	"github.com/maxlaverse/synocrypto/pkg/compression"
	"github.com/maxlaverse/synocrypto/pkg/crypto"
	"github.com/maxlaverse/synocrypto/pkg/encoding"
	"github.com/maxlaverse/synocrypto/pkg/log"
)

type encrypter struct {
	options EncrypterOptions
}

func (e *encrypter) Encrypt(in io.Reader, out io.Writer) error {
	encryptionSalt, err := crypto.RandomSalt(8)
	if err != nil {
		return fmt.Errorf("unable to generate random salt: %w", err)
	}

	sessionKey, err := randomSessionKey()
	if err != nil {
		return fmt.Errorf("unable to generate random session key: %w", err)
	}

	sessionKeyHex := bytesToHex(sessionKey)

	metadata := map[string]interface{}{}
	if !e.options.DisableCompression {
		metadata[encoding.MetadataFieldCompress] = 1
	}
	metadata[encoding.MetadataFieldEncrypt] = 1
	metadata[encoding.MetadataFieldSalt] = encryptionSalt
	metadata[encoding.MetadataFieldVersion] = map[string]interface{}{"major": 3, "minor": 1}
	saltedHash, err := crypto.RandomSaltedHash(string(sessionKeyHex))
	if err != nil {
		return fmt.Errorf("error generating random salt for session key hash: %w", err)
	}

	metadata[encoding.MetadataFieldSessionKeyHash] = saltedHash

	if len(e.options.Password) > 0 {
		passwordEncryptedSessionKey, passwordEncryptedSessionKeyHash, err := encryptedSessionKeyByPassword(sessionKeyHex, e.options.Password, encryptionSalt)
		if err != nil {
			return fmt.Errorf("error generating password encrypted key: %w", err)
		}
		metadata[encoding.MetadataFieldEncryptionKey1] = passwordEncryptedSessionKey
		metadata[encoding.MetadataFieldEncryptionKey1Hash] = passwordEncryptedSessionKeyHash
	}

	if len(e.options.PrivateKey) > 0 {
		privateKeyEncryptedSessionKey, privateKeyEncryptedSessionKeyHash, err := encryptedSessionKeyByPrivateKey(sessionKeyHex, e.options.PrivateKey)
		if err != nil {
			return fmt.Errorf("error generating private key encrypted key: %w", err)
		}
		metadata[encoding.MetadataFieldEncryptionKey2] = privateKeyEncryptedSessionKey
		metadata[encoding.MetadataFieldEncryptionKey2Hash] = privateKeyEncryptedSessionKeyHash
	}

	if e.options.Filename != "" {
		metadata[encoding.MetadataFieldFilename] = path.Base(e.options.Filename)
	}

	var hasher hash.Hash
	if !e.options.DisableDigestGeneration {
		metadata[encoding.MetadataFieldDigest] = "md5"
		hasher = md5.New()
		in = io.TeeReader(in, hasher)
	}

	objWriter := encoding.NewWriter(out)
	err = objWriter.WriteMetadata(metadata)
	if err != nil {
		return fmt.Errorf("error writing metadata: %w", err)
	}

	cryptoOut := crypto.NewEncrypterWithPasswordAndSalt(sessionKey, []byte{}, objWriter)

	if !e.options.DisableCompression {
		if e.options.UseExternalLz4Compressor {
			log.Debug("Using external lz4 command for compression")
			in, err = compression.NewLz4CompExternal(in)
		} else {
			log.Debug("Using builtin lz4 compressor")
			in, err = compression.NewLz4CompBuiltin(in)
		}
		if err != nil {
			return fmt.Errorf("unable to initialize the compression: %w", err)
		}
	}

	_, err = io.Copy(cryptoOut, in)
	if err != nil {
		return fmt.Errorf("error copying data: %w", err)
	}

	err = cryptoOut.Close()
	if err != nil {
		return fmt.Errorf("error closing data: %w", err)
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
	return nil
}

func encryptedSessionKeyByPassword(sessionKey []byte, password, encryptionSalt string) (string, string, error) {
	encryptedBytes, err := crypto.EncryptOnceWithPasswordAndSalt([]byte(password), []byte(encryptionSalt), sessionKey)
	if err != nil {
		return "", "", err
	}

	encrypted := base64.StdEncoding.EncodeToString(encryptedBytes)
	saltedHash, err := crypto.RandomSaltedHash(password)
	return encrypted, saltedHash, err
}

func encryptedSessionKeyByPrivateKey(sessionKey []byte, privateKey []byte) (string, string, error) {
	publicKey, err := crypto.PublicKeyFromPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("error extracting public key from private key: '%w'", err)
	}

	res, err := crypto.EncryptOnceWithPublicKey([]byte(publicKey), []byte(sessionKey))
	if err != nil {
		return "", "", fmt.Errorf("error encrypting private key: '%w'", err)
	}

	encrypted := base64.StdEncoding.EncodeToString([]byte(res))
	saltedHash, err := crypto.RandomSaltedHash(publicKey)
	return encrypted, saltedHash, err
}

func bytesToHex(str []byte) []byte {
	data := make([]byte, hex.EncodedLen(len(str)))
	hex.Encode(data, []byte(str))
	return data
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
