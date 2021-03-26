# Synology Cloud Sync decryption in Go

## Overview

A Go library and CLI to decrypt Synology Cloud Sync files.

The file format was originally discovered by [@marnix](https://github.com/marnix)
and translated here [in a sort of specification](ENCRYPTION.md).

## Example

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

_, err = decrypter.Decrypt(encFile, decFile)
if err != nil {
      panic(err)
}
```
