package cmd

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/maxlaverse/synocrypto"
	"github.com/op/go-logging"
	"github.com/urfave/cli/v2"
)

// DecryptOptions holds the options specific to the decryption command
type DecryptOptions struct {
	OutputDir     string
	PrintToStdout bool
}

// NewDecryptCommand returns a command for decrypting a Cloud Sync file
func NewDecryptCommand(log *logging.Logger) *cli.Command {
	var keyOpts KeyOptions
	var opts DecryptOptions
	return &cli.Command{
		Name:    "decrypt",
		Aliases: []string{"d"},
		Usage:   "Decrypts a file",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:        "output-directory",
				Aliases:     []string{"o"},
				Usage:       "Directory where to output the decrypted file",
				EnvVars:     []string{"OUTPUT_DIR"},
				Destination: &opts.OutputDir,
			},
			&cli.BoolFlag{
				Name:        "stdout",
				Usage:       "Print output to stdout",
				Destination: &opts.PrintToStdout,
				Value:       false,
			}}, keyFlags(&keyOpts)...),
		Action: func(c *cli.Context) error {
			if err := checkKeyOptions(c, keyOpts); err != nil {
				return err
			}
			if len(opts.OutputDir) > 0 && opts.PrintToStdout {
				return fmt.Errorf("can't specify an output directory and ask to print the decrypter file to stdout at the same time")
			}
			if len(opts.OutputDir) > 0 && !fileExists(opts.OutputDir) {
				return fmt.Errorf("the specified output directory could not be found")
			}
			return decrypt(log, keyOpts, opts, c.Args().Get(0))
		},
	}
}

func decrypt(log *logging.Logger, keyOpts KeyOptions, cliOpts DecryptOptions, inFilepath string) error {
	opts, err := computeDecrypterOptions(keyOpts)
	if err != nil {
		return err
	}

	inFile, err := os.Open(inFilepath)
	if err != nil {
		return fmt.Errorf("unable to read encrypted file: %w", err)
	}
	defer inFile.Close()

	var outStream io.Writer
	var outFilepath string
	inPlaceDecryption := !cliOpts.PrintToStdout && len(cliOpts.OutputDir) == 0
	if cliOpts.PrintToStdout {
		outStream = os.Stdout
	} else {
		if len(cliOpts.OutputDir) == 0 {
			outFilepath = filenameWithTag(inFilepath, "decrypted")
		} else {
			outFilepath = filepath.Join(cliOpts.OutputDir, path.Base(inFilepath))
			if fileExists(outFilepath) {
				return fmt.Errorf("the output file '%s' already exists", outFilepath)
			}
		}
		outStream, err = os.OpenFile(outFilepath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("unable to create decrypted file: %w", err)
		}
		defer outStream.(*os.File).Close()
	}

	decrypter := synocrypto.NewDecrypter(opts)
	err = decrypter.Decrypt(inFile, outStream)
	if err != nil {
		return fmt.Errorf("error decrypting content: %w", err)
	}

	if inPlaceDecryption {
		originalFilepath := filenameWithTag(inFilepath, "original")
		err := os.Rename(inFilepath, originalFilepath)
		if err != nil {
			return fmt.Errorf("error while renaming '%s' to '%s': %w", inFilepath, originalFilepath, err)
		}

		// Close the file before moving it, even if it means closing it again in defer()
		outStream.(*os.File).Close()
		err = os.Rename(outFilepath, inFilepath)
		if err != nil {
			return fmt.Errorf("error while renaming '%s' to '%s': %w", outFilepath, inFilepath, err)
		}
	}
	return nil
}

func filenameWithTag(filename, tag string) string {
	return fmt.Sprintf("%s-%s%s", strings.TrimSuffix(filename, path.Ext(filename)), tag, filepath.Ext(filename))
}
