# Synology Cloud Sync decryption in Go

[![GoDoc](https://godoc.org/github.com/maxlaverse/synocrypto?status.svg)](https://godoc.org/github.com/maxlaverse/synocrypto)
[![test](https://github.com/maxlaverse/synocrypto/actions/workflows/workflow.yaml/badge.svg)](https://github.com/maxlaverse/synocrypto/actions/workflows/workflow.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxlaverse/synocrypto)](https://goreportcard.com/report/github.com/maxlaverse/synocrypto)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/tag/maxlaverse/synocrypto.svg?style=social)](https://github.com/maxlaverse/synocrypto/tags)

## Overview

A Go library and dependency-free CLI to decrypt Synology Cloud Sync files on various Operating Systems (Linux, macOS, Windows).

The file format was originally discovered by [@marnix](https://github.com/marnix)
and is summarized [in this document](ENCRYPTION.md).

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
   encrypt, e   Encrypts a file
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

### Encryption Support

The library has a prototype implementation for encrypting files.
Files encrypted with it can often (always?) be decrypted using the library again.
However, Cloudsync sometimes fails to decrypt them with errors related to compression:
```
Sep 16 22:54:25 [ERROR] lz4-processor.cpp(239): LZ4F_decompress LOGIC ERROR: inbuf_consumed='0' inbuf_size='8'
Sep 16 22:54:25 [ERROR] pipeline.cpp(119): Failed when read
Sep 16 22:54:25 [ERROR] encrypt-file.cpp(148): Failed when reading from decryptor.
Sep 16 22:54:25 [WARNING] worker.cpp(3211): Worker (15): Failed to decrypt file
```

I haven't had the time to debug this further.

[releases]: https://github.com/maxlaverse/synocrypto/releases