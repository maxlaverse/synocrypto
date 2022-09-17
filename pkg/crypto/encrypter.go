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

	"github.com/maxlaverse/synocrypto/pkg/log"
)

const (
	// maxBlockSize is the maximum size an object can have. If the limit
	// is cross, CloudSync complains about it and says it considers the file
	// to be corrupted.
	maxBlockSize = 8192
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
	blockIndex       int
}

func (e *encrypter) Write(p []byte) (int, error) {
	return e.writeInChunks(p, maxBlockSize)
}

func (e *encrypter) writeInChunks(p []byte, size int) (int, error) {
	written := 0
	for start := 0; start <= len(p); start += size {
		end := start + size
		if end > len(p) {
			end = len(p)
		}

		n, err := e.write(p[start:end])
		written = written + n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (e *encrypter) write(p []byte) (int, error) {
	if e.hasBufferedBlock {
		err := e.encryptAndFlushBuffer()
		if err != nil {
			return -1, err
		}
	}

	if len(p) != 0 {
		e.bufferData(p)
	}
	return len(p), nil
}

func (e *encrypter) bufferData(p []byte) {
	log.Debugf("Buffering %d bytes of plain data", len(p))
	e.bufferedBlock = make([]byte, len(p))
	copy(e.bufferedBlock, p)

	e.hasBufferedBlock = true
}

func (e *encrypter) encryptAndFlushBuffer() error {
	encryptedBlock := make([]byte, len(e.bufferedBlock))

	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("CryptBlocks paniced: %v", r)
			}
		}()

		e.mode.CryptBlocks(encryptedBlock, e.bufferedBlock)
		return
	}()
	if err != nil {
		return fmt.Errorf("error crypting block: %w", err)
	}

	e.blockIndex += 1
	log.Debugf("Block #%d - Writting out %d encrypted bytes ", e.blockIndex, len(encryptedBlock))
	_, err = e.out.Write(encryptedBlock)
	if err != nil {
		return fmt.Errorf("error flushing block: %w", err)
	}

	e.hasBufferedBlock = false
	return nil
}

func (e *encrypter) encryptAndFlushBufferWithPadding() error {
	if !e.hasBufferedBlock {
		return nil
	}

	var err error
	sizeBeforePadding := len(e.bufferedBlock)
	e.bufferedBlock, err = pkcs7Pad(e.bufferedBlock, e.mode.BlockSize())
	log.Debugf("Adding %d bytes of padding to the plain data", len(e.bufferedBlock)-sizeBeforePadding)

	if err != nil {
		return fmt.Errorf("unable to pad data: %w", err)
	}
	return e.encryptAndFlushBuffer()
}

func (e *encrypter) Close() error {
	err := e.encryptAndFlushBufferWithPadding()

	if v, ok := e.out.(io.WriteCloser); ok {
		if err := v.Close(); err != nil {
			return err
		}
	}
	return err
}
