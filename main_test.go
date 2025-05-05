package main

import (
	"bytes"
	"io"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func TestMainHelp(t *testing.T) {
	helpArgs := [][]string{{}, {"-h"}, {"--help"}}

	helpMessages := []*regexp.Regexp{
		regexp.MustCompile(`^Print message digest hashes of stdin.\n`),
		regexp.MustCompile(`Usage:\n  dgst \[flags\]\n  dgst \[command\]`),
		regexp.MustCompile(`Flags:\n  -`),
		regexp.MustCompile(`\nUse "dgst \[command\] --help" for more information about a command.\n$`),
	}

	for _, args := range helpArgs {
		buf := &bytes.Buffer{}
		dgstCmd = newDgstCmd()
		dgstCmd.SetArgs(args)
		dgstCmd.SetOut(buf)
		main()
		output := buf.String()

		for _, helpMessage := range helpMessages {
			if !helpMessage.MatchString(output) {
				t.Fatalf(
					"unexpected help message\n:  wanted: %q\n     got: %q",
					helpMessage.String(), output)
			}
		}
	}
}

func TestKnownOutputs(t *testing.T) {
	const theQuickBrownFox = "The quick brown fox jumps over the lazy dog"

	// args, stdin, output
	for i, example := range []struct {
		args   []string
		input  io.Reader
		output []byte
	}{
		// MD5 tests including all flag combinations.
		{[]string{"md5"}, nil, []byte("d41d8cd98f00b204e9800998ecf8427e\n")},
		{[]string{"md5", "-a"}, nil, []byte("1B2M2Y8AsgTpgAmY7PhCfg==\n")},
		{[]string{"md5", "--base64"}, nil, []byte("1B2M2Y8AsgTpgAmY7PhCfg==\n")},
		{[]string{"md5", "-b"}, nil, []byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}},
		{[]string{"md5", "--binary"}, nil, []byte{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}},
		{[]string{"md5", "--sri"}, nil, []byte("md5-1B2M2Y8AsgTpgAmY7PhCfg==\n")},
		{[]string{"md5", "--hmac-key", "key"}, strings.NewReader(theQuickBrownFox), []byte("80070713463e7749b90c2dc24911e275\n")},

		// SHA family
		{[]string{"sha1"}, nil, []byte("da39a3ee5e6b4b0d3255bfef95601890afd80709\n")},
		{[]string{"sha-1"}, nil, []byte("da39a3ee5e6b4b0d3255bfef95601890afd80709\n")},
		{[]string{"sha256"}, nil, []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")},
		{[]string{"sha-256"}, nil, []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")},
		{[]string{"sha512"}, nil, []byte("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n")},
		{[]string{"sha-512"}, nil, []byte("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\n")},

		// HMAC
		{[]string{"md5", "--hmac-key=key"}, strings.NewReader(theQuickBrownFox), []byte("80070713463e7749b90c2dc24911e275\n")},
		{[]string{"sha1", "--hmac-key=key"}, strings.NewReader(theQuickBrownFox), []byte("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9\n")},
		{[]string{"sha256", "--hmac-key=key"}, strings.NewReader(theQuickBrownFox), []byte("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8\n")},
		{[]string{"sha512", "--hmac-key=key"}, strings.NewReader(theQuickBrownFox), []byte("b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a\n")},

		// Various
		{[]string{"blake2-256", "--base64"}, nil, []byte("DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g=\n")},
		{[]string{"blake2-256", "--blake-key=deadbeef", "--base64"}, nil, []byte("aSYX2bvjUGB+3hPEZrOTwL7m8UR0ESVGP5Zm1z5kh2U=\n")},
		{[]string{"crc32", "--polynomial-table=castagnoli"}, strings.NewReader("OK\n"), []byte("d6a6fc12\n")},
	} {
		dgstCmd = newDgstCmd()
		dgstCmd.SetArgs(example.args)
		dgstCmd.SetIn(example.input)
		output := new(bytes.Buffer)
		dgstCmd.SetOut(output)
		main()
		actual := output.Bytes()
		if !reflect.DeepEqual(actual, example.output) {
			t.Fatalf("unexpected output for example #%v (args=%#v, see input):"+
				"\n  wanted: %#v\n     got: %#v",
				i+1, example.args, example.output, actual)
		}
	}
}
