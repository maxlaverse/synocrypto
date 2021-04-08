package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataCmdErrorOnMissingArgument(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "metadata"})
	assert.EqualError(t, err, "the path to an encrypted file must be provided as argument")
}

func TestMetadataCmd(t *testing.T) {
	testApp := newFakeApp()

	waitForOutput, restoreStdout := captureStdout(t)
	defer restoreStdout()

	err := testApp.Run([]string{"synocrypto", "metadata", "-p", "synocrypto", "../testdata/test.txt"})
	assert.NoError(t, err)

	output := waitForOutput()
	assert.Equal(t, "METADATA KEY        VALUE\ncompress            1\ndigest              md5\nenc_key1            1JsDqSXozGU9zGgcgFRBxSlPZF+3ht67+/4zA80Z/lfm/6+UU/Sjtm4Nq0Kf6G3on0KpMb53AvAmICjXtdJr16sOZJUPoUaAqrZjLsczCoc=\nenc_key2            ZVPJvuf1Ac7drz/Xyt2eZJVaZ168XYLsnIrodJ4AsGGQfgKqD18zZJz3E0GwFhlY1U2dB9DGrjKscfWd+B/VxOMf9vco5hFVGQrEwpBTPx2JvqvWDQ59QLzWssnSSs4J/U8PEjs5n+VNFgvEqnb5IUqWtkjawwL/WyvA0sBKcTg7j4mhTFQtGrTtISRAjuvUzpNl/PTIDVuJ1tyvRDQ0za2wY31TnkmgzMsDbDXfn5NzsHuIwy8KEoeDVmV0Mqp5pGhSOpOm587O12T+rtOsFNV7WhIO4WXqQpxa/YwdFVZ1S0ky9Ca/4QjuiKgYufAXU02QAB6fSmNBXL/JZ0DLCw==\nencrypt             1\nfile_md5            aad5c59fbedfc6e9212bcd794648229a\nfile_name           test.txt\nkey1_hash           5xpmRJJia-96d9d9c103f4891bf23e4f5dcd978edc\nkey2_hash           STUjnQyYYKb825729cf0524d0c92e1d19882718fc0\nsalt                9Al0M24f\nsession_key_hash    Xe5VpcaB1K09798eed2b8f6b31cc6ace8011b744ef\nversion             map[major:3 minor:1]\n", output)
}
