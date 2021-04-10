package synocrypto

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"github.com/maxlaverse/synocrypto/pkg/compression"
	"github.com/maxlaverse/synocrypto/pkg/crypto"
	"github.com/maxlaverse/synocrypto/pkg/encoding"
	"github.com/maxlaverse/synocrypto/pkg/log"
)

// Decrypter is a generic interface for decryption
type Decrypter interface {
	Decrypt(f io.Reader, w io.Writer) error
	Metadata(f io.Reader) (map[string]interface{}, error)
}

// NewDecrypter returns a new decrypter
func NewDecrypter(opts DecrypterOptions) Decrypter {
	return &decrypter{options: opts}
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

// SetLogger allows to collect additional information through the `log.Logger` interface.
func SetLogger(l log.Logger) {
	log.SetLogger(l)
}

type decrypter struct {
	options DecrypterOptions
}

// Metadata only reads the metadata of a file and then stops, returned a map and an error in
// case of troubles.
func (d *decrypter) Metadata(in io.Reader) (map[string]interface{}, error) {
	objReader := encoding.NewReader(in)

	// Starts reading the encrypted file and return a channel with data objects once the metadata
	// have been read.
	dataChan, err := objReader.DataChannel()
	if err != nil {
		return nil, fmt.Errorf("error reading metadata: %w", err)
	}

	// Discard the data
	for range dataChan {
	}
	return objReader.Metadata(), nil
}

// Decrypt reads an encrypted file and writes it into an output writer after having decrypted it.
// Depending on the file's metadata, Decrypt also decompresses the file and verifies its integrity.
func (d *decrypter) Decrypt(in io.Reader, out io.Writer) error {
	objReader := encoding.NewReader(in)

	// Starts reading the encrypted file and return a channel with data objects once the metadata
	// have been read.
	dataChan, err := objReader.DataChannel()
	if err != nil {
		return fmt.Errorf("error reading metadata: %w", err)
	}

	// Pipe a hasher if we have information allowing us to verify its integrity.
	var hasher hash.Hash
	hashName, ok := objReader.Metadata()[encoding.MetadataFieldDigest]
	if !ok {
		log.Warningf("Unable to locate hash function field in the metadata. Integrity of the output won't be checked.", encoding.MetadataFieldDigest)
	} else if hashName == "md5" {
		log.Debugf("Output integrity verified through md5")
		hasher = md5.New()
		out = io.MultiWriter(hasher, out)
	} else {
		log.Warningf("Unsupported hash function: '%s'. Integrity of the output won't be checked", hashName)
	}

	// Pipe a decompressor if the encrypted file is compressed
	compressionEnabled, ok := objReader.Metadata()[encoding.MetadataFieldCompress]
	if !ok {
		log.Warningf("Unable to locate compression field in the metadata. Assuming the data is compressed.", encoding.MetadataFieldDigest)
		compressionEnabled = 1
	}
	if compressionEnabled == 1 {
		if d.options.UseExternalLz4Decompressor {
			log.Debug("Using external lz4 command for decompression")
			out, err = compression.NewLz4External(out)
		} else {
			log.Debug("Using builtin lz4 decompressor")
			out, err = compression.NewLz4Builtin(out)
		}
		if err != nil {
			return fmt.Errorf("unable to initialize the decompression: %w", err)
		}
	} else {
		log.Debug("Compression is disabled")
	}

	// Retrieve the session key required to decrypt the data
	sessionKey, err := retrieveSessionKey(d.options.Password, d.options.PrivateKey, objReader.Metadata())
	if err != nil {
		return fmt.Errorf("unable to initialize the decryption: %w", err)
	}

	// Pipe a decrypter with this session key
	out = crypto.NewWithPasswordAndSalt(sessionKey, []byte{}, out)

	// Read the data
	for data := range dataChan {
		_, err = out.Write(data)
		if err != nil {
			return fmt.Errorf("error writing to output stream: %w", err)
		}
	}
	if objReader.Error() != nil {
		return fmt.Errorf("error while reading the encodings: %w", objReader.Error())
	}

	// Close and finish
	if v, ok := out.(io.WriteCloser); ok {
		err = v.Close()
		if err != nil {
			return fmt.Errorf("error while closing stream: %w", err)
		}
	}

	// Check the file's integrity if we can
	if hasher != nil {
		actualFileDigest := hex.EncodeToString(hasher.Sum(nil))
		expectedHash := objReader.Metadata()[encoding.MetadataFieldMd5Digest]
		if actualFileDigest != expectedHash {
			if !d.options.IgnoreChecksumMismatch {
				return fmt.Errorf("file digest doesn't match (computed: '%s', read:'%s')", actualFileDigest, expectedHash)
			}
			log.Errorf("file digest doesn't match (computed: '%s', read:'%s')", actualFileDigest, expectedHash)
		} else {
			log.Debugf("Checksum matched: %s", actualFileDigest)
		}
	}
	return nil
}

func retrieveSessionKey(password string, privateKey []byte, metadata map[string]interface{}) (sessionKey []byte, err error) {
	if len(password) > 0 {
		sessionKey, err = retrieveSessionKeyByPassword(password, metadata)
		if err != nil {
			log.Errorf("Unable to retrieve session key by password: %v", err)
		}
	}

	if len(privateKey) > 0 {
		sessionKey, err = retrieveSessionKeyByPrivateKey(privateKey, metadata)
		if err != nil {
			log.Errorf("Unable to retrieve session key by private key: %v", err)
		}
	}

	if len(sessionKey) == 0 {
		return nil, fmt.Errorf("not enough information available to decrypt the session key")
	}

	sessionKeyHash, hasSessionKeyHash := metadata[encoding.MetadataFieldSessionKeyHash]
	if !hasSessionKeyHash {
		log.Warning("Unable to find the hash of the session key. Won't be able to verify the validity of the session key")
	} else {
		if !crypto.IsSaltedHashOf(sessionKeyHash.(string), string(sessionKey)) {
			return nil, fmt.Errorf("sessionKey hash don't match (expected: '%s')", sessionKeyHash)
		}
	}

	if _, ok := metadata[encoding.MetadataFieldSalt]; ok {
		// Special handling when a salt is given, which probably means when the version is > 1.0.0
		sessionKey = hexToBytes(sessionKey)
	}
	return
}

func retrieveSessionKeyByPrivateKey(privateKey []byte, metadata map[string]interface{}) ([]byte, error) {
	encryptionKey2, hasEncryptionKey := metadata[encoding.MetadataFieldEncryptionKey2]

	if !hasEncryptionKey {
		return nil, fmt.Errorf("missing session key encrypted by private key")
	}
	encryptionKey2, err := base64.StdEncoding.DecodeString(encryptionKey2.(string))
	if err != nil {
		return nil, fmt.Errorf("error decoding encrypted key2: '%w'", err)
	}

	return crypto.DecryptOnceWithPrivateKey(privateKey, []byte(encryptionKey2.([]byte)))
}

func retrieveSessionKeyByPassword(password string, metadata map[string]interface{}) ([]byte, error) {
	passwordHash, hasPasswordHash := metadata[encoding.MetadataFieldEncryptionKey1Hash]
	if !hasPasswordHash {
		log.Warning("File is missing the hash of the encrypted key1. Won't be able to check if password is valid")
	} else {
		if !crypto.IsSaltedHashOf(passwordHash.(string), password) {
			return nil, fmt.Errorf("password hash don't match (expected: '%s')", passwordHash.(string))
		}
	}

	encryptionKey1, hasEncryptionKey := metadata[encoding.MetadataFieldEncryptionKey1]
	salt, hasSalt := metadata[encoding.MetadataFieldSalt]

	if !hasEncryptionKey {
		return nil, fmt.Errorf("missing session key encrypted by password")
	} else if !hasSalt {
		version := retrieveVersion(metadata)
		if len(version) > 0 && version[0] > 1 {
			return nil, fmt.Errorf("missing expected salt (version: %v)", version)
		}
		log.Warningf("missing salt (version: %v)", version)
		salt = ""
	}

	encryptionKey1, err := base64.StdEncoding.DecodeString(encryptionKey1.(string))
	if err != nil {
		return nil, fmt.Errorf("error decoding encrypted key1: '%w'", err)
	}

	sessionKey, err := crypto.DecryptOnceWithPasswordAndSalt([]byte(password), []byte(salt.(string)), encryptionKey1.([]byte))
	if err != nil {
		return nil, fmt.Errorf("error decrypting encrypted key1: '%w'", err)
	}
	return sessionKey, nil
}

func retrieveVersion(metadata map[string]interface{}) []int {
	version, hasVersion := metadata[encoding.MetadataFieldVersion]
	if hasVersion {
		major, hasMajorVersion := version.(map[string]interface{})["major"]
		minor, hasMinorVersion := version.(map[string]interface{})["minor"]
		if hasMajorVersion && hasMinorVersion {
			return []int{major.(int), minor.(int)}
		} else if hasMajorVersion {
			return []int{major.(int)}
		}
	}
	return []int{}
}

func hexToBytes(str []byte) []byte {
	data := make([]byte, 32)
	hex.Decode(data, []byte(str))
	return data
}
