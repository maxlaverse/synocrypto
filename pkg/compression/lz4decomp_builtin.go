package compression

import (
	"fmt"
	"io"

	"github.com/maxlaverse/synocrypto/pkg/log"
	lz4 "github.com/pierrec/lz4/v4"
)

type lz4Builtin struct {
	zr            io.Reader
	pw            *io.PipeWriter
	done          chan struct{}
	pipeExitError error
}

// NewLz4DecompBuiltin returns a new lz4 decompressor based on
func NewLz4DecompBuiltin(out io.Writer) (io.WriteCloser, error) {
	pr, pw := io.Pipe()

	b := &lz4Builtin{
		zr:   lz4.NewReader(pr),
		pw:   pw,
		done: make(chan struct{}),
	}
	go b.copyRoutine(out)

	return b, nil
}

func (b *lz4Builtin) copyRoutine(out io.Writer) {
	defer close(b.done)

	n, err := io.Copy(out, b.zr)
	if err != nil {
		b.pipeExitError = err
		log.Errorf("Decompression copy completed (%d bytes, err: %v)", n, err)
	} else {
		log.Debugf("Decompression copy completed (%d bytes)", n)
	}

	b.pw.Close()
}

func (b *lz4Builtin) Write(p []byte) (int, error) {
	if b.pipeExitError != nil {
		return -1, fmt.Errorf("decompression failed: can't accept more data: %v", b.pipeExitError)
	}

	n, err := b.pw.Write(p)
	if err != nil && err == io.ErrClosedPipe {
		return n, b.Close()
	} else if err != nil {
		return n, fmt.Errorf("error writing to internal pipe: %w", err)
	}
	return n, nil
}

func (b *lz4Builtin) Close() error {
	<-b.done
	if b.pipeExitError != nil {
		return fmt.Errorf("decompression failed: %w", b.pipeExitError)
	}
	return nil
}
