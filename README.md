# Synology Cloud Sync decryption in Go

[![GoDoc](https://godoc.org/github.com/maxlaverse/synocrypto?status.svg)](https://godoc.org/github.com/maxlaverse/synocrypto)
[![test](https://github.com/maxlaverse/synocrypto/actions/workflows/workflow.yaml/badge.svg)](https://github.com/maxlaverse/synocrypto/actions/workflows/workflow.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxlaverse/synocrypto)](https://goreportcard.com/report/github.com/maxlaverse/synocrypto)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/maxlaverse/synocrypto.svg?style=social)](https://github.com/maxlaverse/synocrypto/tags)

## Overview

A Go library and CLI to decrypt Synology Cloud Sync files.

The file format was originally discovered by [@marnix](https://github.com/marnix)
and translated [into a description document here](ENCRYPTION.md).

## Command line tool

### Installation

Assuming you have the go toolchain installed:
```
go install github.com/maxlaverse/synocrypto/cli/synocrypto
```

You can also download pre-compiled binaries from the [releases] page.

### Usage
```
NAME:
   synocrypto - A cli for decrypting Synology Cloud Sync files

USAGE:
   synocrypto [global options] command [command options] [arguments...]

COMMANDS:
   decrypt, d   Decrypts a file
   metadata, m  Displays the metadata of a file
   version      Prints the version
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug     outputs additional debug lines (default: false)
   --help, -h  show help (default: false)
```

## Library

### Usage

```go
encFile, err := os.Open("./my-encrypted-file.jpg")
if err != nil {
      panic(err)
}
defer encFile.Close()

decFile, err := os.OpenFile("./my-decrypted-file.jpg", os.O_CREATE|os.O_WRONLY, 0644)
if err != nil {
      panic(err)
}
defer decFile.Close()

decrypter := synocrypto.NewDecrypter(synocrypto.DecrypterOptions{
      Password: "synocrypto",
})

err = decrypter.Decrypt(encFile, decFile)
if err != nil {
      panic(err)
}
```

[releases]: https://github.com/maxlaverse/synocrypto/releases