package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

type Options struct {
	Base64 bool
}

func main() {
	options := &Options{}

	rootCmd := &cobra.Command{
		Use:               "dgst",
		Short:             "Compute and print message digest hash values of stdin.",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	for name, hfn := range hashes {
		cmd := &cobra.Command{
			Use: name, Short: fmt.Sprintf("Compute and print the %q digest of stdin.", name),
			Run: printHash(name, hfn, options),
		}
		rootCmd.AddCommand(cmd)
	}

	rootCmd.Flags().BoolVarP(&options.Base64, "base64", "A", options.Base64,
		"print hash values encoded as base64")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var hashes = map[string]func() hash.Hash{
	"md4": md4.New,
	"md5": md5.New,

	"sha1":     sha1.New,
	"sha256":   sha256.New,
	"sha384":   sha512.New384,
	"sha512":   sha512.New,
	"sha3-224": sha3.New224,
	"sha3-256": sha3.New256,
	"sha3-384": sha3.New384,
	"sha3-512": sha3.New512,

	"blake2-256": blakeEmptyKey(blake2b.New256),
	"blake2-384": blakeEmptyKey(blake2b.New384),
	"blake2-512": blakeEmptyKey(blake2b.New512),

	"ripemd160": ripemd160.New,
}

func printHash(name string, hfn func() hash.Hash, o *Options) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		h := hfn()
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatalf("FATAL: failed to compute %q hash from stdin: %v", name, err)
		}
		var hash string
		if o.Base64 {
			hash = base64.StdEncoding.EncodeToString(h.Sum(nil))
		} else {
			hash = hex.EncodeToString(h.Sum(nil))
		}
		fmt.Println(hash)
	}
}

func blakeEmptyKey(f func([]byte) (hash.Hash, error)) func() hash.Hash {
	h, err := f(nil)
	if err != nil {
		panic(err)
	}
	return func() hash.Hash { return h }
}
