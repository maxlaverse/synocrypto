# Synology Cloud Sync - Encryption Description

Last revised: 2022-09-17.

Synology Inc distributes a software named Cloud Sync. It allows customers to synchronize the
files of their Network Attached Storage with the storage provider of their choice (e.g. AWS S3,
Synology C2, Google Drive). Cloud Sync offers the possibility to encrypt files on the fly before
sending them to a remote location. 

This document is intended for developers willing to decrypt those files using any programming
language. It's unofficial and not supported by Synology Inc in any way. It was built after
analyzing the [synology-decrypt] tool written by [@marnix].

There are three main sections in this page:
* [Data Types](#data-types) describes how the data is organized at the lowest level.
  It gives the information required to make sense of the blobs of bytes.
* [File Structure](#file-structure) explains at a higher level how the blobs of data are combined
  together into an encrypted file.
* [Data Encryption](#data-encryption) lists the steps required to decrypt and decompress the data.

## Data Types

A Cloud Sync encrypted file starts with a magic header and continues with consecutive objects of
different types (e.g. `string`, `integer`).

### Magic Header

The magic header is the string `__CLOUDSYNC_ENC__` followed by its md5 digest form
`d8d6ba7b9df02ef39a33ef912a91dc56`. Right after this header comes the actual data in the form of
objects.

### Objects

An object is a sequence of bytes which represent a certain type of data. An object always starts
with a lead byte indicating its type, and continues with the actual data. How the actual data
is organized is type specific.

| Type      | Lead Byte |
| --------- |:---------:|
| `integer` | `[1]`     |
| `string`  | `[16]`    |
| `bytes`   | `[17]`    |
| `dict`    | `[55]`    |


#### Integer

Following the lead byte, an `integer` starts with one byte indicating on how many remaining bytes
the value is encoded. Those following bytes are big endian ordered.

**Example 1**: the sequence of bytes `[1, 3]` represents the integer value 3 :

  - `[1]` : is the number of bytes to encode the number 3
  - `[3]` : the actual value 3

**Example 2**: the sequence of bytes `[2, 18, 52]` represents the integer value 4660 :

  - `[2]` : is the number of bytes to encode the value 4660
  - `[18]` : the most significant byte (18 * 256 = 4608)
  - `[52]` : the less significant byte  (52), which gives 4608 + 52 = 4660

#### Bytes

Following the lead byte, a `bytes` sequence starts with two bytes indicating the number of bytes
that compose the actual data. Those following bytes are big endian ordered.

**Example**: the byte sequence `[0, 3, 109, 100, 53]` represents a byte object of `[109, 100, 53]`:

  - `[0, 3]` : length of the sequence, 3 in this case
  - `[109, 100, 53]`: the actual sequence

#### String

A `string` is just a string representation of a `byte` value.

**Example**: the byte sequence `[0, 3, 109, 100, 53]` represents a string object `md5`:

  - `[0, 3]` : length of the sequence, 3 in this case
  - `[109, 100, 53]`: the actual sequence which represents `m`, `d` and `5`

#### Dict

Following the lead byte, a `dict` is a succession of keys and values.

The first byte indicate the type of the key. It can only be `[16] (string)` or the special value
`[40] (stop)` which indicates the end of the dictionnary. The key should be read as a string.

Following the key, a byte then indicates the type of the value. The value can be anything,
including a dictionnary. The dictionnary should be read until the next lead byte is `[40] (stop)`.

**Example**: the byte sequence `[16, 0, 5, 109, 97, 106, 111, 114, 1, 1, 3, 16, 0, 5, 109, 105, 110, 111, 114, 1, 1, 1, 40]`
is a dictionnary with two keys: `major: 3` and `minor: 1`

  - `16` : indicates the key is a string
    - `[0, 5]` : length of the string (5)
    - `[109, 97, 106, 111, 114]`: ASCII representation of "major"

  - `[1]` : indicates the value is an integer
    - `[1]` : length of the byte (1)
    - `[3]` : value of the byte

  - `[16]` : indicates the next key is a string
    - `[0, 5]` : length of the string (5)
    - `[109, 105, 110, 111, 114]`: ASCII representation of "minor"

  - `[1]` : indicates the value is an integer
    - `[1]` : length of the byte (1)
    - `[1]` : value of the byte

  - `[40]` : stop byte indicating the end of the dictionnary


## File Structure

An encrypted file is a magic header followed by a sequence of `dict` objects. Those dictionary
always have a key named `type` which can have two values: either `metadata` or `data`.

### Metadata Dictionary

When a dictionnary has a `type` field set to `metadata`, all other keys of the dictionnary
represent metadata. Metadata are extr-information that help setting everything up to decrypt a
file. As of today, the following metadata fields have been encountered:

| Name               | Type      | Description                                                                                   |
| ------------------ |:---------:|-----------------------------------------------------------------------------------------------|
| `compress`         | `integer` | 1 if the file is compressed                                                                   |
| `encrypt`          | `integer` | 1 if the file is encrypted                                                                    |
| `file_name`        | `string`  | original name of the file                                                                     |
| `digest`           | `string`  | the hash function used to compute a digest of the file (`md5`)                                |
| `enc_key1`         | `string`  | encryption key 1                                                                              |
| `key1_hash`        | `string`  | hash of the encryption key 1, for verification                                                |
| `enc_key2`         | `string`  | encryption key 2                                                                              |
| `key2_hash`        | `string`  | hash of the encryption key 2, for verification                                                |
| `salt`             | `string`  | 8-bytes salt used to encrypt the password as `enc_key1`                                       |
| `version`          | `dict`    | is the version of Cloud Sync used to encrypt the file. It has two keys: `major` and `minor`   |
| `session_key_hash` | `string`  | hash of the session key used to actually encrypt the data, for verification                   |
| `file_md5`         | `string`  | contains the checksum of the file, once decrypted and decompressed, for verification          |

Note: `key1_hash`, `key2_hash` and `session_key_hash` are each salted with 3 different randomly-generated alphabetical 10-bytes long strings

### Data Dictionary

When a dictionnary has a `type` field set to `data`, it also has another field named `data` which
contains an encrypted chunk of data as bytes.

### Order

Because the metadata are necessary in order to decrypt the data, they're the first object that
comes after the magic header. Then comes the data. Finally, the stream of objects is concluded
with a metadata containing the `file_md5` key in order to verify the file's integrity.

## Encryption

### Introduction

Each file is encrypted using its own randomly generated 32 bytes `session key`. This key itself is
encrypted and added to the file in two metadata fields:
* `enc_key1`: this is the `session key` encrypted by using the password entered when initializing
  the Cloud Sync task. The `key1_hash` allows to verify if the password provided for the decryption
  matches what was used for encryption.
* `enc_key2`: this is the `session key` encrypted by using a randomly generated pair of RSA keys.
  The user gets to download those keys as an archive once a Cloud Sync task is configured. The
  `key2_hash` allows to verify if the private key provided for the decryption matches what was used
  for encryption.

The `session_key_hash` helps verifying if the `session key` was correctly decrypted. Finally, the
`session key` is used to initialize an AES-256 decrypter.

An overview can also be found in this [Cloud Sync White paper].

### Retrieving the Session Key by Password

The `enc_key1` field is the `session key` encrypted by password. It can be recovered using the
password provided when setting up the Cloud Sync task, and the `salt` field in the metadata.

#### Generating the key/iv for decryption
First the password and `salt` need to be transformed into a `key` and `iv` (Initialization Vector).
which are then used to decrypt the `enc_key1` value.

The transformation from a password and salt to a `key` and `iv` is done by a
[proprietary method of OpenSSL]. Since it's not standard, it's not always possible to find an
implementation for a given language.

A pseudo code of that function would be the following:

```
  function OpenSSLKDF(password []byte, salt []byte, iteration=1000 int, keyLen=32 int, ivLen=16 int):
    derived_key = []byte                          // initialized our derived_key as an empty byte array
    while length(derived_key) < keyLen + ivLen:   // we stop when we have enough data
      // Compute the hash of derived_key + password + salt
      hasher = new_md5_hasher()
      if derived_key not empty:
        hasher.update(derived_key)
      hasher.update(password)
      hasher.update(salt)

      last_sum = hasher.digest()

      // Rehash this hash "iteration" number of times
      for i=1, i<iteration; i++:
        hasher = new_md5_hasher()
        hasher.update(last_sum)
        last_sum = hasher.digest()
      end

      // Append the result to our derived_key
      derived_key = derived_key + last_sum

      key = derived_key[0:keyLen] 
      iv = derived_key[ivLen:]
      return key, iv
    end
```

**Example**:  given the password `synocrypto`, the salt `hnEnPWyu`, and 1000 iterations, 
this function would return:
```
key = 29a63e045f53f7a1dbae700050bbb4a90836d1e5c42167b79efcf09015ab4eca
iv = 0b18273c8a0231910d7f771ef33196d2
```

#### Initialize decryption
The `key/iv` should be used to initialize an AES CDC Decrypter. The base64 decoded value of the
`enc_key1` can then be decrypted to give the `session key`.

**Example**:  given the base64 value of `enc_key1=0d7B6AujRw865OyzuwUKBuv9XLsdz1Cia8iUSHq//Sdn629DHgFLt5Xbb3N7+EM4cdqGx08+cJ66Ocf+bD79YIt0007iF5/+TXy1qwiHfwc=`,
The resulting `session key` should be `6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22`.

#### Verify password
It's possible to verify if the password given by the user corresponds to the one used to encrypt
a file. If that's the case, the following equality should be true:
```
key1_hash[:10] + md5(key1_hash[:10] + password) == key1_hash
```

### Retrieving the Session Key by Private Key

The `enc_key2` field is the `session key` encrypted by private key. It's possible to decrypt
the value is most languages using RSA-OAEP.

**Example**: Given the private key:
```
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtBz8vOnQLVH3pdKtbPUnl0FgWAgHoWGbVhP0JdSeE8h8tfL5
p0i0FB/O8PDrxeLMuJBB3MFAez+oHXTBxigFHWD6AShD9fcNaPaRTBmV/hiRu5qN
OuIw/yv8V9UR+j3/FASCthdte3QEAMpJG6EstGfqmnx5vsFcOEQ9CFNqV6fnOp5z
mDf1ebC7B9LeiM/YCoGFqatXyA6J5Z0rCCsurIKPXWa6WBsbGRDS66l3/U8KRuIc
LOYJQfKH5ze4tb/COduCmMjLKrLOCK/jQ7QuI7yZFlfG3eVOl71Oaevz8Lx9Ozse
0PH9gIYYtyVMwR90bbX77rlQdfekicWJHxRkYQIDAQABAoIBABO1NEZrgxbiaCmh
0s4gSRO42JTpVARpjLiveECHckCR6Gt0SbLvNp0ZGeitQ+8kMOhlCH/iOW8C+R83
/lfzWxPq35Au2rjYLoR0rlNYXVwvTgrsD1YJF/lj07m8m7n4/KcxEyhfieA/Qozf
lX5LdXvL/xSmWB/yQmf5t3/ouLMcgid+EKdC2dBXHHsOs63IuwFkAdNpI8wLZJmL
YmB4V/AWFDQsJR0YGIF9aat2VQy53mIfgU7Hc5wOQ24/9vG8yEGxBbzPL1XrFZPt
HEHgp4IJbRD3PZNF+ZFz2JncEPKiys6wXcH/PWUm/49/XvIbRmsWn+m0EHZjZVc3
XfBrq00CgYEA1/1LJdEGejsO4bRWnmC6k/wxYtbH48T8r7CNnyLFS8x9EpKhw4J3
S1kGUVB9cU5BUkNrZMTjnsWKHAmA0m5ZSOVc+FtIjvOUtO9Df1kTwuw+QIrZeu0K
iY7uMCBY2NMh35LrQGq8inpwGIfSZsHkaahPMQDSTzZROJdOt3sT7O8CgYEA1Xpd
C2bAWPdqKhJvQ/WEp8KF2xbBETmu1chkel92ywxcAyfKGD2WwoU/Q6L0UR1nNpFo
h0X/HiSFSOXpQ63U20WrSqpsIZ2YbAdMnIAaWqCqibl/tI6pZzOGwPrVcTKIdvpX
xy6ElKyb/ZjIOfHfBrA69C+gK+SoUsr9uJ97Y68CgYBsdS+gHLdA95kAc3svamkm
WHRAKpQTZt5wJprm9yHVbyi7A9ChCUl4F4sZl+510BLzCRHLdybJmm5Ap/D9OhYx
iaNGvyfPSLc6qA7fys4milS0OkT8+jzZWGF43zVeI58V0oO5RB/K9bKGTuWzXdeh
yreBZuU0i5T7ctc/QVl/FwKBgQDLb353vQWUQsNDMKojwzcVf8R70qVOOwAn7n4C
ODNGsJKG10Y574dZ/A0b8ZCONE0FrXBFaSkDmp4BqEexHVj5VN01nE7Lghmc6R/T
DCkRMIcUFFhkwochN/M0uFTrONLfPxajU+s4m31UIGK/BYYaI5sq1K/45ECcFaHQ
bPrzNQKBgBfiPbiOY314j52CPA33KmD7NriW10B2twK3ZZX0E6hWCvL/5jFphXOa
tTCd///b9/oNSZyzHIf69oH0pTs26MBj4HAIYMphOBPdZWIMyBsP/4nM/6df5JXk
E29KR9oDG+brb+NXAKRPXMqKok9+qqjfZ6J/rufou6ONwSFMe68a
-----END RSA PRIVATE KEY-----
```

And the base64 decoded value of `enc_key2`: `kBbiJllccHDtABrzsCsWqqNDitS73zPywor7UG2JIausa5kWfdQ7jF9zkJfKTgPhnCRi69EM3wHs3Kl/3OoZdgftU5m/jN1tL9ou9L4kT2wRucjRMALMpJxHvEXEijrUg3qQYuJdR3OaXwrUG4HTV4mmMztLqXcY75p+TzFFg5LEwej8zXEojmbefClORp0/heoskU+UnzchU1o96MBM3BuYOlGbLGezONPe/TZmW33Tytuf4LJNEtdPviiaQ1XInJt90C7cIyCoI95jNp2DtMhQZ5r27InmbDCyZFb3gCpp6TH6zzSru361tg5ftmpmufA61BEus7ZVqKn7C2N0qg==`

- `6C1FD4FA9566048ACE57BE85FC600ED914799F2A1AD31212D6678D30AC015D22` is the hexadecimal
  representation of the `session key` once decrypted

It's possible to verify if the public key given by the user corresponds to the one used to encrypt
a file. If that's the case, the following equality should be true:
```
key2_hash[:10] + md5(key2_hash[:10] + public_key) == key2_hash
```

With public key in the following form:
```
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtBz8vOnQLVH3pdKtbPUnl0FgWAgHoWGbVhP0JdSeE8h8tfL5p0i0
FB/O8PDrxeLMuJBB3MFAez+oHXTBxigFHWD6AShD9fcNaPaRTBmV/hiRu5qNOuIw
/yv8V9UR+j3/FASCthdte3QEAMpJG6EstGfqmnx5vsFcOEQ9CFNqV6fnOp5zmDf1
ebC7B9LeiM/YCoGFqatXyA6J5Z0rCCsurIKPXWa6WBsbGRDS66l3/U8KRuIcLOYJ
QfKH5ze4tb/COduCmMjLKrLOCK/jQ7QuI7yZFlfG3eVOl71Oaevz8Lx9Ozse0PH9
gIYYtyVMwR90bbX77rlQdfekicWJHxRkYQIDAQAB
-----END RSA PUBLIC KEY-----
```


### Verify session key
It's possible to verify if the session key was correctly decrypted. In this case, the following
equality should be true:
```
session_key_hash[:10] + md5(session_key_hash[:10] + session_key) == session_key_hash
```

### Decrypting data

Assuming the session key has been retrieved, it can be used as password in `OpenSSLKDF()` with only
one iteration this time, and no salt. The `key/iv` can then be used to initialize an AES CDC Decrypter.

From there, everytime an object of `type=data` is encountered when reading the encrypted file, its
data can be decrypted with our AES decrypter. The result is likely to be compressed, which is
discussed in the next point. A special attention should be paid to the last decrypted block of data,
for which the pkcs7 padding must be removed.

There is one important twist with the value of the `session key`. If the metadata `version->major`
is greater than `1`, then it's not the `session key` that should be given to `OpenSSLKDF()` but its
unhexed form.

**Example**: for the session key starting with `6C1FD4F*`

  - `[108, 31, 212, 250, ...]` : is the right `session key` to be used in this situation
  - `[36, 43, 31, 46, ...]` : would be wrong

### Compression

The decrypter outputs data that is LZ4 compressed using Block Dependency. This can be decompressed
by piping it to [lz4].

### File Digest

If the metadata has a `digest` field, the decompressed output can feed a hasher of that name
(e.g. `md5`). The result digest can be verified against the `file_md5` metadata field.


## References

* [Cloud Sync White paper]
* [StackExchange discussion about the Encryption Algorithm]
* [StackExchange discussion on the retrieval of key/iv from a password+salt]

Big thanks to [@marnix] who uncovered the structure of the Cloud Sync files. More information can
be found in his repository: https://github.com/marnix/synology-decrypt

[synology-decrypt]: https://github.com/marnix/synology-decrypt
[proprietary method of OpenSSL]: https://github.com/openssl/openssl/blob/13a574d8bb2523181f8150de49bc041c9841f59d/crypto/evp/evp_key.c#L78-L154
[Cloud Sync White paper]: https://web.archive.org/web/20160606190954/https://global.download.synology.com/download/Document/WhitePaper/Synology_Cloud_Sync_White_Paper-Based_on_DSM_6.0.pdf
[StackExchange discussion about the Encryption Algorithm]: https://security.stackexchange.com/questions/124838/which-file-encryption-algorithm-is-used-by-synologys-cloud-sync-feature
[StackExchange discussion on the retrieval of key/iv from a password+salt]: https://security.stackexchange.com/questions/29106/openssl-recover-key-and-iv-by-passphrase/117654#117654
[lz4]: https://github.com/lz4/lz4
[@marnix]: https://github.com/marnix