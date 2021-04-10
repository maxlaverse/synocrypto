package cmd

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var (
	// Version is the current version of the CLI
	Version = "0.0.1"

	// GitRevision is set during build time with the current git revision
	GitRevision = "unknown"
)

// NewVersionCommand returns a new version command
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
