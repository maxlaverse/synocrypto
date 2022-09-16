package main

import (
	"fmt"
	"os"

	"github.com/maxlaverse/synocrypto"
	"github.com/maxlaverse/synocrypto/cli/synocrypto/cmd"
	"github.com/op/go-logging"
	"github.com/urfave/cli/v2"
)

var (
	logger = &logging.Logger{}

	logFormat = logging.MustStringFormatter(`%{time:15:04:05.000} ▶ %{level:.5s} %{message}`)
)

func main() {
	debugMode := false
	app := &cli.App{
		Name:  "synocrypto",
		Usage: "A cli for decrypting Synology Cloud Sync files",
		Flags: []cli.Flag{&cli.BoolFlag{
			Name:        "debug",
			Value:       false,
			Usage:       "outputs additional debug lines",
			Destination: &debugMode,
		}},
		Before: configureLogging(&debugMode),
		Commands: []*cli.Command{
			cmd.NewDecryptCommand(logger),
			cmd.NewEncryptCommand(logger),
			cmd.NewMetadataCommand(logger),
			cmd.NewVersionCommand(),
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func configureLogging(debugMode *bool) cli.BeforeFunc {
	return func(_ *cli.Context) error {
		backend := logging.NewLogBackend(os.Stderr, "", 0)
		formatter := logging.NewBackendFormatter(backend, logFormat)
		leveledBackend := logging.AddModuleLevel(formatter)
		if *debugMode {
			leveledBackend.SetLevel(logging.DEBUG, "")
		} else {
			leveledBackend.SetLevel(logging.INFO, "")
		}

		logger.SetBackend(leveledBackend)
		synocrypto.SetLogger(logger)
		return nil
	}
}
