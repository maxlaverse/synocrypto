package synocrypto

import (
	"io"

	"github.com/maxlaverse/synocrypto/pkg/log"
)

// SetLogger allows to collect additional information through the `log.Logger` interface.
func SetLogger(l log.Logger) {
	log.SetLogger(l)
}

// Decrypter is a generic interface for decryption
type Decrypter interface {
	Decrypt(f io.Reader, w io.Writer) error
	Metadata(f io.Reader) (map[string]interface{}, error)
}

// DecrypterOptions holds the options that can be used for decryption
type DecrypterOptions struct {
	// Password used in the setup of Cloud Sync encryption task.
	Password string

	// PrivateKey automatically exported setting up a Cloud Sync encryption task for the first
	// time. It's usually named 'private.pem' in the exported key file.
	PrivateKey []byte

	// UseExternalLz4Decompressor enables decrompression using an external `lz4` command that must
	// be installed separately.
	UseExternalLz4Decompressor bool

	// IgnoreChecksumMismatch prints
	IgnoreChecksumMismatch bool
}

// NewDecrypter returns a new decrypter
func NewDecrypter(opts DecrypterOptions) Decrypter {
	return &decrypter{options: opts}
}

// Encrypter is a generic interface for encryption
type Encrypter interface {
	Encrypt(f io.Reader, w io.Writer) error
}

type EncrypterOptions struct {
	// Password used in the setup of Cloud Sync encryption task.
	Password string

	// PrivateKey automatically exported setting up a Cloud Sync encryption task for the first
	// time. It's usually named 'private.pem' in the exported key file.
	PrivateKey []byte

	// UseExternalLz4Decompressor enables crompression using an external `lz4` command that must
	// be installed separately.
	UseExternalLz4Compressor bool

	// Filename is the name for the file to be added in the metadata
	Filename string

	// DisableCompression allows to disable compression. This is not supported by DMS
	// which tries to decompress the data anyway and fails.
	DisableCompression bool

	// DisableDigestGeneration allows to disable the md5 checksum computation.
	DisableDigestGeneration bool
}

// NewEncrypter returns a new encrypter
func NewEncrypter(opts EncrypterOptions) Encrypter {
	return &encrypter{options: opts}
}
