package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// DecryptOnceWithPasswordAndSalt decrypts a single blob of data with
// an AES decrypter initialized by password and salt
func EncryptOnceWithPasswordAndSalt(password, salt, decodedData []byte) ([]byte, error) {
	var b bytes.Buffer
	sessionKeyEncrypter := NewEncrypterWithPasswordAndSalt(password, salt, &b)

	_, err := sessionKeyEncrypter.Write(decodedData)
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted key1: '%w'", err)
	}

	err = sessionKeyEncrypter.Close()
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted key1: '%w'", err)
	}

	return b.Bytes(), nil
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
	if d.hasBufferedBlock {
		lastBlockEncrypted := make([]byte, len(d.bufferedBlock))

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("paniced: %v", r)
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

	d.bufferedBlock = p
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
