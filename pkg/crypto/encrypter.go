package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

const (
	// maxBlockSize is the maximum size an object can have. If the limit
	// is cross, CloudSync complains about it and says it considers the file
	// to be corrupted. This size seems to be 8192 but we're being conservative.
	maxBlockSize = 4096
)

// EncryptOnceWithPasswordAndSalt encrypts a single blob of data with
// an AES decrypter initialized by password and salt
func EncryptOnceWithPasswordAndSalt(password, salt, decodedData []byte) ([]byte, error) {
	var b bytes.Buffer
	sessionKeyEncrypter := NewEncrypterWithPasswordAndSalt(password, salt, &b)

	_, err := sessionKeyEncrypter.Write(decodedData)
	if err != nil {
		return nil, fmt.Errorf("error encrypting sessionKey: '%w'", err)
	}

	err = sessionKeyEncrypter.Close()
	if err != nil {
		return nil, fmt.Errorf("error encrypting sessionKey: '%w'", err)
	}

	return b.Bytes(), nil
}

// EncryptOnceWithPublicKey encrypts a single blob of data using an RSA public key
func EncryptOnceWithPublicKey(publicKey []byte, decodedData []byte) ([]byte, error) {
	publicKeyBlock, _ := pem.Decode(publicKey)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("no public key found in pem")
	}

	key, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}

	encryptedData, err := encryptOAEP(key, decodedData)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt data using public key: %w", err)
	}

	return encryptedData, nil
}

func encryptOAEP(public *rsa.PublicKey, p []byte) ([]byte, error) {
	hash := sha1.New()
	random := rand.Reader

	step := public.Size() - 2*hash.Size() - 2

	var outputEncrypted bytes.Buffer
	for start := 0; start < len(p); start += step {
		end := start + step
		if end > len(p) {
			end = len(p)
		}
		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, p[start:end], nil)
		if err != nil {
			return nil, err
		}
		outputEncrypted.Write(encryptedBlockBytes)
	}

	return outputEncrypted.Bytes(), nil
}

func NewEncrypterWithPasswordAndSalt(password, salt []byte, out io.Writer) io.WriteCloser {
	key, iv := keyIV(password, salt)
	return newAESCBCEncrypter(key, iv, out)
}

func newAESCBCEncrypter(key, iv []byte, out io.Writer) io.WriteCloser {
	block, _ := aes.NewCipher(key)
	return &encrypter{
		mode: cipher.NewCBCEncrypter(block, iv),
		out:  out,
	}
}

type encrypter struct {
	hasBufferedBlock bool
	mode             cipher.BlockMode
	bufferedBlock    []byte
	out              io.Writer
}

func (d *encrypter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return d.write(nil)
	}

	written := 0
	for start := 0; start < len(p); start += maxBlockSize {
		end := start + maxBlockSize
		if end > len(p) {
			end = len(p)
		}

		n, err := d.write(p[start:end])
		written = written + n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (d *encrypter) write(p []byte) (int, error) {
	if d.hasBufferedBlock {
		lastBlockEncrypted := make([]byte, len(d.bufferedBlock))

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("CryptBlocks paniced: %v", r)
				}
			}()

			d.mode.CryptBlocks(lastBlockEncrypted, d.bufferedBlock)
			return
		}()
		if err != nil {
			return -1, fmt.Errorf("error crypting block: %w", err)
		}

		n, err := d.out.Write(lastBlockEncrypted)
		if err != nil {
			return n, fmt.Errorf("error flushing block: %w", err)
		}
		d.hasBufferedBlock = false
	}

	// We have to return len(p) instead of what was really written
	// to the output, or io.Copy() returns 'short write' error.
	if len(p) == 0 {
		return len(p), nil
	}

	if len(d.bufferedBlock) < len(p) {
		d.bufferedBlock = make([]byte, len(p))
	} else if len(d.bufferedBlock) > len(p) {
		d.bufferedBlock = d.bufferedBlock[:len(p)]
	}
	copy(d.bufferedBlock, p)

	d.hasBufferedBlock = true
	return len(p), nil
}

func (d *encrypter) flushBufferWithPadding() (int, error) {
	if !d.hasBufferedBlock {
		return -1, nil
	}

	var err error
	d.bufferedBlock, err = pkcs7Pad(d.bufferedBlock, d.mode.BlockSize())
	if err != nil {
		return -1, fmt.Errorf("unable to pad data: %w", err)
	}

	return d.Write(nil)
}

func (d *encrypter) Close() error {
	_, err := d.flushBufferWithPadding()

	if v, ok := d.out.(io.WriteCloser); ok {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return err
}
