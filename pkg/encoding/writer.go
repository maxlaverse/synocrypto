package encoding

import (
	"crypto/md5"
	"fmt"
	"io"
)

type Writer interface {
	Write([]byte) (int, error)
	WriteMetadata(metadata map[string]interface{}) error
}

// NewWriter returns a new encoding Writer.
func NewWriter(f io.Writer) Writer {
	return &objectWriter{
		f: f,
	}
}

type objectWriter struct {
	f                      io.Writer
	cloudSyncHeaderWritten bool
}

func (w *objectWriter) Write(data []byte) (int, error) {
	if !w.cloudSyncHeaderWritten {
		panic("can't write data before any metadata")
	}

	dataObj := map[string]interface{}{}
	dataObj[objectFieldType] = objectValueTypeData
	dataObj[objectFieldData] = data

	return len(data), writeObject(dataObj, w.f)
}

func (w *objectWriter) WriteMetadata(metadata map[string]interface{}) error {
	if !w.cloudSyncHeaderWritten {
		err := writeCloudSyncHeader(w.f)
		if err != nil {
			return err
		}
		w.cloudSyncHeaderWritten = true
	}

	metadata[objectFieldType] = objectValueTypeMetadata
	return writeObject(metadata, w.f)
}

func writeCloudSyncHeader(f io.Writer) error {
	_, err := f.Write([]byte(cloudSyncFileHeader))
	if err != nil {
		return fmt.Errorf("error writing Cloud Sync's file header: %w", err)
	}

	md5hash := fmt.Sprintf("%x", md5.Sum([]byte(cloudSyncFileHeader)))
	_, err = f.Write([]byte(md5hash))
	if err != nil {
		return fmt.Errorf("error writing Cloud Sync's hashed file header: %w", err)
	}
	return nil
}
