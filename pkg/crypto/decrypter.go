package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	aes256KeySizeBytes = 32

	rsaPublicKeyBegin = "-----BEGIN RSA PUBLIC KEY-----\n"
	rsaPublicKeyEnd   = "-----END RSA PUBLIC KEY-----\n"
	rsaLineMaxLength  = 64
)

type decrypter struct {
	hasBufferedData bool
	mode            cipher.BlockMode
	lastBlock       []byte
	out             io.Writer
}

// PublicKeyFromPrivateKey generates the public key corresponding to a given
// private key
func PublicKeyFromPrivateKey(privateKey []byte) (string, error) {
	privateKeyBlock, _ := pem.Decode(privateKey)
	if privateKeyBlock == nil {
		return "", fmt.Errorf("no private key found in pem")
	}
	key, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("unable to parse private key: %w", err)
	}

	publicKey := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	var b bytes.Buffer
	b.WriteString(rsaPublicKeyBegin)
	for i := 0; i < len(publicKey)/rsaLineMaxLength; i++ {
		b.WriteString(publicKey[i*rsaLineMaxLength:i*rsaLineMaxLength+rsaLineMaxLength] + "\n")
	}
	b.WriteString(publicKey[(len(publicKey)/rsaLineMaxLength)*rsaLineMaxLength:] + "\n")
	b.WriteString(rsaPublicKeyEnd)

	return b.String(), nil
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
	sessionKeyDecrypter := NewDecrypterWithPasswordAndSalt(password, salt, &b)
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

// NewDecrypterWithPasswordAndSalt returns an AES decrypter initialized by password and salt
func NewDecrypterWithPasswordAndSalt(password, salt []byte, out io.Writer) io.WriteCloser {
	key, iv := keyIV(password, salt)
	return newAESCBCDecrypter(key, iv, out)
}

func newAESCBCDecrypter(key, iv []byte, out io.Writer) io.WriteCloser {
	block, _ := aes.NewCipher(key)
	return &decrypter{
		mode: cipher.NewCBCDecrypter(block, iv),
		out:  out,
	}
}

// Write always buffers the decrypted data and writes it on the next call to Write() or Close()
func (d *decrypter) Write(p []byte) (int, error) {
	var n int
	if d.hasBufferedData {
		var err error
		n, err = d.out.Write(d.lastBlock)
		if err != nil {
			return n, fmt.Errorf("error flushing buffered block: %w", err)
		}
		d.hasBufferedData = false
	}

	if len(p) == 0 {
		return n, nil
	}

	if len(d.lastBlock) < len(p) {
		d.lastBlock = make([]byte, len(p))
	} else if len(d.lastBlock) > len(p) {
		d.lastBlock = d.lastBlock[:len(p)]
	}

	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()

		d.mode.CryptBlocks(d.lastBlock, p)
		d.hasBufferedData = true
		return
	}()
	return n, err
}

func (d *decrypter) writeLastBlock() (int, error) {
	if !d.hasBufferedData {
		return -1, nil
	}
	var err error
	d.lastBlock, err = pkcs7Unpad(d.lastBlock, d.mode.BlockSize())
	if err != nil {
		return -1, fmt.Errorf("unable to unpad data: %w", err)
	}

	return d.Write(nil)
}

func (d *decrypter) Close() error {
	_, err := d.writeLastBlock()

	if v, ok := d.out.(io.WriteCloser); ok {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return err
}
