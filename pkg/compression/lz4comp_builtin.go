package compression

import (
	"fmt"
	"io"

	lz4 "github.com/pierrec/lz4/v4"
)

type lz4CompressorBuiltin struct {
	zw io.WriteCloser
	pr io.Reader
	pw *io.PipeWriter
}

// NewLz4CompBuiltin returns a new lz4 compressor based on
// github.com/pierrec/lz4
//
// DISCLAIMER: As of today, it doesn't support Block Dependency encryption
//             which is required for CloudSync.
func NewLz4CompBuiltin(in io.Reader) (io.Reader, error) {
	pr, pw := io.Pipe()
	b := &lz4CompressorBuiltin{
		zw: lz4.NewWriter(pw),
		pr: pr,
		pw: pw,
	}
	go b.copyRoutine(in)

	return b, nil
}

func (b *lz4CompressorBuiltin) copyRoutine(in io.Reader) {
	_, err := io.Copy(b.zw, in)
	b.zw.Close()
	if err != nil {
		b.pw.CloseWithError(fmt.Errorf("error copying to compression: %w", err))
	} else {
		b.pw.Close()
	}
}

func (b *lz4CompressorBuiltin) Read(p []byte) (int, error) {
	buf := make([]byte, len(p))
	bytesCount := 0
	for {
		buf := buf[0 : len(p)-bytesCount]
		n, err := b.pr.Read(buf)
		copy(p[bytesCount:], buf[0:n])
		bytesCount = bytesCount + n
		if err != nil || bytesCount == len(p) {
			return bytesCount, err
		}
	}
}
