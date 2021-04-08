package cmd

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/maxlaverse/synocrypto"
	"github.com/urfave/cli/v2"
)

type KeyOptions struct {
	Password       string
	PasswordFile   string
	PrivateKeyFile string
	IgnoreChecksum bool
}

func keyFlags(keyOpts *KeyOptions) []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "password",
			Aliases:     []string{"p"},
			Usage:       "Password used to setup the Cloud Sync task",
			EnvVars:     []string{"PASSWORD"},
			Destination: &keyOpts.Password,
		},
		&cli.StringFlag{
			Name:        "password-file",
			Aliases:     []string{"P"},
			Usage:       "Path to a file containing the password used to setup the Cloud Sync task",
			EnvVars:     []string{"PASSWORD_FILE"},
			Destination: &keyOpts.PasswordFile,
		},
		&cli.StringFlag{
			Name:        "key-file",
			Aliases:     []string{"k"},
			Usage:       "Private key used to setup the Cloud Sync task (e.g. private.pem)",
			EnvVars:     []string{"KEY_FILE"},
			Destination: &keyOpts.PrivateKeyFile,
		},
		&cli.BoolFlag{
			Name:        "ignore-checksum",
			Usage:       "Ignore checksum mismatches",
			Destination: &keyOpts.IgnoreChecksum,
			Value:       false,
		},
	}
}

func checkKeyOptions(c *cli.Context, keyOpts KeyOptions) error {
	if c.NArg() > 1 {
		return fmt.Errorf("only one argument expected")
	} else if c.NArg() == 0 {
		return fmt.Errorf("the path to an encrypted file must be provided as argument")
	}

	if !fileExists(c.Args().Get(0)) {
		return fmt.Errorf("the encrypted file could not be found")
	}

	if len(keyOpts.Password) == 0 && len(keyOpts.PasswordFile) == 0 && len(keyOpts.PrivateKeyFile) == 0 {
		return fmt.Errorf("either a password, password file or private key must be provided")
	}
	if len(keyOpts.PrivateKeyFile) > 0 && !fileExists(keyOpts.PrivateKeyFile) {
		return fmt.Errorf("the specified private key could not be found")
	}
	if len(keyOpts.PasswordFile) > 0 && !fileExists(keyOpts.PasswordFile) {
		return fmt.Errorf("the specified password file could not be found")
	}
	return nil
}

func computeDecrypterOptions(keyOpts KeyOptions) (synocrypto.DecrypterOptions, error) {
	opts := synocrypto.DecrypterOptions{
		Password:               keyOpts.Password,
		IgnoreChecksumMismatch: keyOpts.IgnoreChecksum,
	}
	if len(keyOpts.PrivateKeyFile) > 0 {
		var err error
		opts.PrivateKey, err = ioutil.ReadFile(keyOpts.PrivateKeyFile)
		if err != nil {
			return opts, fmt.Errorf("unable to read private key: %w", err)
		}
	}

	if len(keyOpts.PasswordFile) > 0 {
		data, err := ioutil.ReadFile(keyOpts.PasswordFile)
		if err != nil {
			return opts, fmt.Errorf("unable to read password file: %w", err)
		}
		opts.Password = string(data)
	}

	return opts, nil
}

func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil && !os.IsNotExist(err)
}
