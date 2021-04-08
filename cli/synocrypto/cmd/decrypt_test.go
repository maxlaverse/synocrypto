package cmd

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDecryptCmdErrorOnMissingArgument(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt"})
	assert.EqualError(t, err, "the path to an encrypted file must be provided as argument")
}

func TestDecryptCmdErrorOnTooManyArguments(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "a-test-file", "another-test-file"})
	assert.EqualError(t, err, "only one argument expected")
}

func TestDecryptCmdErrorWhenEncryptedFileAbsent(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "something-that-doesnt.exist"})
	assert.EqualError(t, err, "the encrypted file could not be found")
}

func TestDecryptCmdErrorWhenNoKeyNoPassword(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "../testdata/test.txt"})
	assert.EqualError(t, err, "either a password, password file or private key must be provided")
}

func TestDecryptCmdErrorOnWrongPassword(t *testing.T) {
	defer os.Remove("../testdata/test-decrypted.txt")

	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-p", "wrong-password", "../testdata/test.txt"})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "error decrypting content: ")
	}
}

func TestDecryptCmdErrorOnAbsentPrivateKey(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-k", "something-that-doesnt.exist", "../testdata/test.txt"})
	assert.EqualError(t, err, "the specified private key could not be found")
}

func TestDecryptCmdErrorOnWrongPrivateKey(t *testing.T) {
	defer os.Remove("../testdata/test-decrypted.txt")

	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-k", "../testdata/test.txt", "../testdata/test.txt"})
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "error decrypting content: ")
	}
}

func TestDecryptCmdErrorOnExistingOutputFile(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-p", "doesntmatter", "-o", "../testdata", "../testdata/test.txt"})
	assert.EqualError(t, err, "the output file '../testdata/test.txt' already exists")
}

func TestDecryptCmdErrorOnNonExistingOutputDirectory(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-p", "doesntmatter", "-o", "something-missing", "../testdata/test.txt"})
	assert.EqualError(t, err, "the specified output directory could not be found")
}

func TestDecryptCmdErrorWhenSpecifyingStdoutAndOutputDir(t *testing.T) {
	testApp := newFakeApp()
	err := testApp.Run([]string{"synocrypto", "decrypt", "-p", "doesntmatter", "-o", "../testdata", "--stdout", "../testdata/test.txt"})
	assert.EqualError(t, err, "can't specify an output directory and ask to print the decrypter file to stdout at the same time")
}

func TestDecryptCmdDecryptionByPasswordStdout(t *testing.T) {
	testApp := newFakeApp()

	waitForOutput, restoreStdout := captureStdout(t)
	defer restoreStdout()

	err := testApp.Run([]string{"synocrypto", "decrypt", "-p", "synocrypto", "--stdout", "../testdata/test.txt"})
	assert.NoError(t, err)

	output := waitForOutput()
	assert.Equal(t, "This is something we wanted to decrypt. The END!", output)
}

func TestDecryptCmdDecryptionByPasswordFileStdout(t *testing.T) {
	testApp := newFakeApp()

	waitForOutput, restoreStdout := captureStdout(t)
	defer restoreStdout()

	err := testApp.Run([]string{"synocrypto", "decrypt", "-P", "../testdata/password.txt", "--stdout", "../testdata/test.txt"})
	assert.NoError(t, err)

	output := waitForOutput()
	assert.Equal(t, "This is something we wanted to decrypt. The END!", output)
}

func TestDecryptCmdDecryptionByPrivateKeyStdout(t *testing.T) {
	testApp := newFakeApp()

	waitForOutput, restoreStdout := captureStdout(t)
	defer restoreStdout()

	err := testApp.Run([]string{"synocrypto", "decrypt", "-k", "../testdata/private.pem", "--stdout", "../testdata/test.txt"})
	assert.NoError(t, err)

	output := waitForOutput()
	assert.Equal(t, "This is something we wanted to decrypt. The END!", output)
}

func TestDecryptCmdDecryptionInOutputDirectory(t *testing.T) {
	testApp := newFakeApp()
	tempdir, err := ioutil.TempDir("", "output-test")
	if !assert.NoError(t, err) {
		t.Fatal()
	}
	defer os.RemoveAll(tempdir)

	err = testApp.Run([]string{"synocrypto", "decrypt", "-p", "synocrypto", "-o", tempdir, "../testdata/test.txt"})
	assert.NoError(t, err)

	output, err := ioutil.ReadFile(path.Join(tempdir, "test.txt"))
	assert.NoError(t, err)
	assert.Equal(t, "This is something we wanted to decrypt. The END!", string(output))
}

func TestDecryptCmdDecryptionInPlace(t *testing.T) {
	testApp := newFakeApp()
	tempdir, err := ioutil.TempDir("", "output-test")
	if !assert.NoError(t, err) {
		t.Fatal()
	}
	defer os.RemoveAll(tempdir)
	testFile := path.Join(tempdir, "test2.txt")

	copyFileContents("../testdata/test.txt", testFile)

	err = testApp.Run([]string{"synocrypto", "decrypt", "-p", "synocrypto", testFile})
	assert.NoError(t, err)

	output, err := ioutil.ReadFile(testFile)
	assert.NoError(t, err)
	assert.Equal(t, "This is something we wanted to decrypt. The END!", string(output))
}
