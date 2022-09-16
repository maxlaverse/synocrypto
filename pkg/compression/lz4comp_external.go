package compression

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

type lz4CompExternal struct {
	cmd *exec.Cmd
	pr  *io.PipeReader
}

// NewLz4CompExternal returns a new LZ4 compressor using an external
// lz4 command. This command must be installed prior execution.
func NewLz4CompExternal(in io.Reader) (io.Reader, error) {
	cmd := exec.Command("lz4", "-BD", "-B4096")
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = os.Stderr
	cmd.Stdin = in

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("unable to start lz4 process: %w", err)
	}

	go func() {
		cmd.Wait()
		pw.Close()
	}()

	return &lz4CompExternal{pr: pr, cmd: cmd}, nil
}

func (b *lz4CompExternal) Read(p []byte) (int, error) {
	return b.pr.Read(p)
}
