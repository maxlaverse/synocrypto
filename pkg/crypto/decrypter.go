package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	aes256KeySizeBytes = 32
)

type decrypter struct {
	mode      cipher.BlockMode
	lastBlock []byte
	out       io.Writer
}

// DecryptOnceWithPrivateKey decrypts a single blob of data using an RSA private key
func DecryptOnceWithPrivateKey(privateKeyData, encodedData []byte) ([]byte, error) {
	privateKeyBlock, _ := pem.Decode(privateKeyData)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("no private key could be read from the provided data")
	}
	pri, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not load private key: %w", err)
	}

	hash := sha1.New()
	random := rand.Reader
	decryptedData, err := rsa.DecryptOAEP(hash, random, pri, encodedData, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data using private key: %w", err)
	}

	return decryptedData, nil
}

// DecryptOnceWithPasswordAndSalt decrypts a single blob of data with
// an AES decrypter initialized by password and salt
func DecryptOnceWithPasswordAndSalt(password, salt, encodedData []byte) ([]byte, error) {
	var b bytes.Buffer
	sessionKeyDecrypter := NewWithPasswordAndSalt(password, salt, &b)
	_, err := sessionKeyDecrypter.Write(encodedData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted key1: '%w'", err)
	}
	err = sessionKeyDecrypter.Close()
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted key1: '%w'", err)
	}

	return b.Bytes(), nil
}

// NewWithPasswordAndSalt returns an AES decrypter initialized by password and salt
func NewWithPasswordAndSalt(password, salt []byte, out io.Writer) io.WriteCloser {
	iteration := 1
	if len(salt) > 0 {
		iteration = 1000
	}

	// AES-256 is used as indicated in this "Cloud Sync White Paper":
	// https://web.archive.org/web/20160606190954/https://global.download.synology.com/download/Document/WhitePaper/Synology_Cloud_Sync_White_Paper-Based_on_DSM_6.0.pdf
	key, iv := openSSLKDF(password, salt, iteration, aes256KeySizeBytes, aes.BlockSize, md5.New)
	return newAESCBCDecrypter(key, iv, out)
}

func newAESCBCDecrypter(key, iv []byte, out io.Writer) io.WriteCloser {
	block, _ := aes.NewCipher(key)
	return &decrypter{
		mode: cipher.NewCBCDecrypter(block, iv),
		out:  out,
	}
}

func (d *decrypter) Write(p []byte) (n int, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("critical failure while decrypting")
		}
	}()

	if len(d.lastBlock) > 0 {
		n, err = d.out.Write(d.lastBlock)
	}
	d.lastBlock = make([]byte, len(p))
	if len(p) == 0 {
		return n, err
	}
	d.mode.CryptBlocks(d.lastBlock, p)
	return n, err
}

func (d *decrypter) Close() error {
	var err error
	d.lastBlock, err = pkcs7Unpad(d.lastBlock, d.mode.BlockSize())
	if err != nil {
		return fmt.Errorf("unable to unpad the last chunk of data: %w", err)
	}
	_, err = d.Write(nil)

	if v, ok := d.out.(io.WriteCloser); ok {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return err
}

// Returns slice of the original data without padding.
// https://golang-examples.tumblr.com/post/98350728789/pkcs-7-padding
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	// check padding
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
