package cmd

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/urfave/cli/v2"
)

func captureStdout(t *testing.T) (func() string, func()) {
	var buf bytes.Buffer
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = writer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, reader)
		close(done)
	}()
	return func() string {
			writer.Close()
			<-done
			return buf.String()
		}, func() {
			os.Stdout = stdout
		}
}

func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func newFakeApp() *cli.App {
	return &cli.App{
		Commands: []*cli.Command{
			NewDecryptCommand(nil),
			NewMetadataCommand(nil),
		},
	}
}
