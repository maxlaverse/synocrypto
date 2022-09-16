package compression

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

type lz4External struct {
	cmd *exec.Cmd
	pw  *io.PipeWriter
}

// NewLz4DecompExternal returns a new LZ4 decompressor using an external
// lz4 command. This command must be installed prior execution.
func NewLz4DecompExternal(out io.Writer) (io.WriteCloser, error) {
	cmd := exec.Command("lz4", "-d")
	cmd.Stdout = out
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("unable to create stdin pipe for lz4: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("unable to start lz4 process: %w", err)
	}

	pr, pw := io.Pipe()
	go func() {
		io.Copy(stdin, pr)
		stdin.Close()
	}()

	return &lz4External{pw: pw, cmd: cmd}, nil
}

func (b *lz4External) Write(p []byte) (int, error) {
	return b.pw.Write(p)
}

func (b *lz4External) Close() error {
	b.pw.Close()
	return b.cmd.Wait()
}
