package cmd

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/maxlaverse/synocrypto"
	"github.com/op/go-logging"
	"github.com/urfave/cli/v2"
)

// EncryptOptions holds the options specific to the encryption command
type EncryptOptions struct {
	OutputDir     string
	PrintToStdout bool
}

// NewEncryptCommand returns a command for encrypting a Cloud Sync file
func NewEncryptCommand(log *logging.Logger) *cli.Command {
	var keyOpts KeyOptions
	var opts EncryptOptions
	return &cli.Command{
		Name:    "encrypt",
		Aliases: []string{"e"},
		Usage:   "Encrypts a file",
		Flags: append([]cli.Flag{
			&cli.StringFlag{
				Name:        "output-directory",
				Aliases:     []string{"o"},
				Usage:       "Directory where to output the encrypted file",
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
				return fmt.Errorf("can't specify an output directory and ask to print the encrypted file to stdout at the same time")
			}
			if len(opts.OutputDir) > 0 && !fileExists(opts.OutputDir) {
				return fmt.Errorf("the specified output directory could not be found")
			}
			return encrypt(log, keyOpts, opts, c.Args().Get(0))
		},
	}
}

func encrypt(log *logging.Logger, keyOpts KeyOptions, cliOpts EncryptOptions, inFilepath string) error {
	opts, err := computeEncrypterOptions(keyOpts)
	if err != nil {
		return err
	}
	opts.Filename = inFilepath

	inFile, err := os.Open(inFilepath)
	if err != nil {
		return fmt.Errorf("unable to read plain file: %w", err)
	}
	defer inFile.Close()

	var outStream io.Writer
	var outFilepath string
	inPlaceEncryption := !cliOpts.PrintToStdout && len(cliOpts.OutputDir) == 0
	if cliOpts.PrintToStdout {
		outStream = os.Stdout
	} else {
		if len(cliOpts.OutputDir) == 0 {
			outFilepath = filenameWithTag(inFilepath, "encrypted")
		} else {
			outFilepath = filepath.Join(cliOpts.OutputDir, path.Base(inFilepath))
			if fileExists(outFilepath) {
				return fmt.Errorf("the output file '%s' already exists", outFilepath)
			}
		}
		outStream, err = os.OpenFile(outFilepath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("unable to create encrypted file: %w", err)
		}
		defer outStream.(*os.File).Close()
	}

	encrypter := synocrypto.NewEncrypter(opts)
	err = encrypter.Encrypt(inFile, outStream)
	if err != nil {
		return fmt.Errorf("error encrypting content: %w", err)
	}

	if inPlaceEncryption {
		originalFilepath := filenameWithTag(inFilepath, "original")
		err := os.Rename(inFilepath, originalFilepath)
		if err != nil {
			return fmt.Errorf("error renaming '%s' to '%s': %w", inFilepath, originalFilepath, err)
		}

		// Close the file before moving it, even if it means closing it again in defer()
		outStream.(*os.File).Close()
		err = os.Rename(outFilepath, inFilepath)
		if err != nil {
			return fmt.Errorf("error renaming '%s' to '%s': %w", outFilepath, inFilepath, err)
		}
	}
	return nil
}
