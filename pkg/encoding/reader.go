package encoding

import (
	"crypto/md5"
	"fmt"
	"io"
	"reflect"

	"github.com/maxlaverse/synocrypto/pkg/log"
)

/*
   See ENCRYPTION.md for more information about the file format
*/

const (
	// MetadataFieldCompress indicates if the file is compressed (int)
	MetadataFieldCompress = "compress"

	// MetadataFieldEncrypt indicates if the file is encrypted (int)
	MetadataFieldEncrypt = "encrypt"

	// MetadataFieldFilename contains the original name of the file (string)
	MetadataFieldFilename = "file_name"

	// MetadataFieldDigest contains the type of digest used to verify the file's consistency after
	// decryption (e.g. md5)
	MetadataFieldDigest = "digest"

	// MetadataFieldEncryptionKey1 contains the Session Key encrypted by password (base64 encoded)
	MetadataFieldEncryptionKey1 = "enc_key1"

	// MetadataFieldEncryptionKey1Hash contains the hash of the key encrypted in enc_key1
	MetadataFieldEncryptionKey1Hash = "key1_hash"

	// MetadataFieldEncryptionKey2 contains the Session Key encrypted by private key (base64 encoded)
	MetadataFieldEncryptionKey2 = "enc_key2"

	// MetadataFieldEncryptionKey2Hash contains the hash of the key encrypted in key2_hash
	MetadataFieldEncryptionKey2Hash = "key2_hash"

	// MetadataFieldSalt is the salt used for computing some hashes (e.g. encryption key 1, session key)
	MetadataFieldSalt = "salt"

	// MetadataFieldVersion is the version of Cloud Sync used to encrypt the file
	MetadataFieldVersion = "version"

	// MetadataFieldSessionKeyHash is the hash of the session key used to actually encrypt the data
	MetadataFieldSessionKeyHash = "session_key_hash"

	// MetadataFieldMd5Digest contains the checksum of the file, once decrypted and decompressed
	MetadataFieldMd5Digest = "file_md5"

	// Magic header that can be found at the beginning of Cloud Sync encrypted files
	cloudSyncFileHeader = "__CLOUDSYNC_ENC__"

	// Different supported object types
	objectFieldType = "type"
	objectFieldData = "data"

	// Values the type of objects can take
	objectValueTypeMetadata = "metadata"
	objectValueTypeData     = "data"
)

type objectReader struct {
	metadata     map[string]interface{}
	readingError error
	f            io.Reader
}

// Reader is an interface allowing to extract low level blob of bytes
// from a Cloud Sync encrypted file.
type Reader interface {
	// DataChannel starts reading the file and stores the metadata it encounter
	// As soon as a data object is read, it returns a channel where the object and all consecutive data object
	// are written too. At the end the channel is closed. If additional metadata are found, they are still processed
	// and the updated variable of the struct is updated
	DataChannel() (chan []byte, error)

	// Error() returns the last error that has occurred when reading the stream through DataChannel()
	Error() error

	// Metadata() simply returns the metadata that have been read so far
	Metadata() map[string]interface{}
}

// NewReader returns a new Reader.
func NewReader(f io.Reader) Reader {
	return &objectReader{
		f:        f,
		metadata: map[string]interface{}{},
	}
}

func (r *objectReader) DataChannel() (chan []byte, error) {
	// The file encrypted by Cloud Sync contain a magic header
	err := verifyCloudSyncHeader(r.f)
	if err != nil {
		return nil, err
	}

	dataChan := make(chan []byte)
	for {
		obj, err := readObject(r.f)
		if err != nil {
			return nil, err
		}
		if obj == nil {
			// Probably means that no objectValueTypeData object as be found before reaching the end of the stream
			return nil, fmt.Errorf("could not find any real data")
		}

		objDict, ok := obj.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unexpected object type '%v': %v", reflect.TypeOf(obj), obj)
		}
		switch objDict[objectFieldType] {
		case objectValueTypeMetadata:
			r.processMetadata(objDict)
		case objectValueTypeData:
			// We've read a data object
			// Return a channel in which we write all consecutive data objects
			log.Debug("Ready to read data")
			go func() {
				dataChan <- objDict[objectFieldData].([]byte)
				go r.readDataToChannel(dataChan)
			}()
			return dataChan, nil
		default:
			return nil, fmt.Errorf("unsupported object type '%s'", objDict[objectFieldType])
		}
	}
}

func (r *objectReader) Metadata() map[string]interface{} {
	return r.metadata
}

func (r *objectReader) Error() error {
	return r.readingError
}

func (r *objectReader) processMetadata(obj map[string]interface{}) {
	for k, v := range obj {
		if k == objectFieldType {
			continue
		}
		r.metadata[k] = v
	}
}

func (r *objectReader) readDataToChannel(dataChan chan []byte) {
	defer func() {
		close(dataChan)
		log.Debug("Done reading data")
	}()

	for {
		obj, err := readObject(r.f)
		if err != nil {
			r.readingError = err
			return
		}
		if obj == nil {
			return
		}
		objDict := obj.(map[string]interface{})
		if objDict[objectFieldType] == objectValueTypeMetadata {
			r.processMetadata(objDict)
		} else if objDict[objectFieldType] == objectValueTypeData {
			dataChan <- objDict[objectFieldData].([]byte)
		}
	}
}

func verifyCloudSyncHeader(f io.Reader) error {
	buf := make([]byte, len(cloudSyncFileHeader))
	_, err := f.Read(buf)
	if err != nil {
		return fmt.Errorf("error reading Cloud Sync's file header: %w", err)
	}

	if string(buf) != cloudSyncFileHeader {
		return fmt.Errorf("the Cloud Sync's header couldn't be found (got: %v, expected: %v)", string(buf), cloudSyncFileHeader)
	}

	buf = make([]byte, 32)
	_, err = f.Read(buf)
	if err != nil {
		return fmt.Errorf("error reading Cloud Sync's hashed file header: %w", err)
	}
	md5hash := fmt.Sprintf("%x", md5.Sum([]byte(cloudSyncFileHeader)))
	if md5hash != string(buf) {
		return fmt.Errorf("the Cloud Sync's header couldn't be found (got: %v, expected: %v)", string(buf), md5hash)
	}
	return nil
}
