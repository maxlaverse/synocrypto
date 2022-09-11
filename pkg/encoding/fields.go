package encoding

/*
   See ENCRYPTION.md for more information about the file format
*/

const (
	// MetadataFieldCompress indicates if the file is compressed (int)
	MetadataFieldCompress = "compress"

	// MetadataFieldEncrypt indicates if the file is encrypted (int)
	MetadataFieldEncrypt = "encrypt"

	// MetadataFieldFilename contains the original name of the file (string)
	MetadataFieldFilename = "file_name"

	// MetadataFieldDigest contains the type of digest used to verify the file's consistency after
	// decryption (e.g. md5)
	MetadataFieldDigest = "digest"

	// MetadataFieldEncryptionKey1 contains the Session Key encrypted by password (base64 encoded)
	MetadataFieldEncryptionKey1 = "enc_key1"

	// MetadataFieldEncryptionKey1Hash contains the hash of the key encrypted in enc_key1
	MetadataFieldEncryptionKey1Hash = "key1_hash"

	// MetadataFieldEncryptionKey2 contains the Session Key encrypted by private key (base64 encoded)
	MetadataFieldEncryptionKey2 = "enc_key2"

	// MetadataFieldEncryptionKey2Hash contains the hash of the key encrypted in key2_hash
	MetadataFieldEncryptionKey2Hash = "key2_hash"

	// MetadataFieldSalt is the salt used for computing some hashes (e.g. encryption key 1, session key)
	MetadataFieldSalt = "salt"

	// MetadataFieldVersion is the version of Cloud Sync used to encrypt the file
	MetadataFieldVersion = "version"

	// MetadataFieldSessionKeyHash is the hash of the session key used to actually encrypt the data
	MetadataFieldSessionKeyHash = "session_key_hash"

	// MetadataFieldMd5Digest contains the checksum of the file, once decrypted and decompressed
	MetadataFieldMd5Digest = "file_md5"

	// Magic header that can be found at the beginning of Cloud Sync encrypted files
	cloudSyncFileHeader = "__CLOUDSYNC_ENC__"

	// Different supported object types
	objectFieldType = "type"
	objectFieldData = "data"

	// Values the type of objects can take
	objectValueTypeMetadata = "metadata"
	objectValueTypeData     = "data"
)
