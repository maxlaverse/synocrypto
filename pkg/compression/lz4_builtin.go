package compression

import (
	"io"

	"github.com/maxlaverse/synocrypto/pkg/log"
	lz4 "github.com/pierrec/lz4/v4"
)

type lz4Builtin struct {
	zr   io.Reader
	pw   *io.PipeWriter
	done chan error
}

// NewLz4Builtin returns a new lz4 decompressor based on
// github.com/pierrec/lz4
func NewLz4Builtin(out io.Writer) (io.WriteCloser, error) {
	pr, pw := io.Pipe()
	zr := lz4.NewReader(pr)

	done := make(chan error)
	go func() {
		n, err := io.Copy(out, zr)
		if err != nil {
			log.Errorf("Decompression copy completed (%d bytes, err: %v)", n, err)
		} else {
			log.Debugf("Decompression copy completed (%d bytes)", n)
		}

		pw.Close()
		done <- err
		log.Debug("Decompression routine exited")
	}()

	return &lz4Builtin{zr: zr, pw: pw, done: done}, nil
}

func (b *lz4Builtin) Write(p []byte) (int, error) {
	return b.pw.Write(p)
}

func (b *lz4Builtin) Close() error {
	err := <-b.done
	close(b.done)
	return err
}
