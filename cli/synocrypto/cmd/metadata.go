package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/maxlaverse/synocrypto"
	"github.com/op/go-logging"
	"github.com/urfave/cli/v2"
)

// NewMetadataCommand returns a command that displays file metadata
func NewMetadataCommand(log *logging.Logger) *cli.Command {
	var keyOpts KeyOptions
	return &cli.Command{
		Name:    "metadata",
		Aliases: []string{"m"},
		Usage:   "Displays the metadata of a file",
		Flags:   keyFlags(&keyOpts),
		Action: func(c *cli.Context) error {
			if err := checkKeyOptions(c, keyOpts); err != nil {
				return err
			}
			return metadata(log, keyOpts, c.Args().Get(0))
		},
	}
}

func metadata(log *logging.Logger, keyOpts KeyOptions, inFilepath string) error {
	opts, err := computeDecrypterOptions(keyOpts)
	if err != nil {
		return err
	}

	inFile, err := os.Open(inFilepath)
	if err != nil {
		return fmt.Errorf("unable to read encrypted file: %w", err)
	}
	defer inFile.Close()

	decrypter := synocrypto.NewDecrypter(opts)
	metadata, err := decrypter.Metadata(inFile)
	if err != nil {
		return fmt.Errorf("error decrypting content: %w", err)
	}

	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 2, 1, 4, ' ', 0)

	fmt.Fprintln(w, "METADATA KEY\tVALUE")

	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%v\n", k, metadata[k])
	}

	w.Flush()
	return nil
}
