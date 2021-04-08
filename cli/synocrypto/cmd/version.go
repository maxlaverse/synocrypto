package cmd

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	Version     = "0.0.1"
	GitRevision = "unknown"
)

func NewVersionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Prints the version",
		Action: func(c *cli.Context) error {
			fmt.Printf("version=%s-%s\n", Version, GitRevision)
			return nil
		},
	}
}
