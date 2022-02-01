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
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

type Options struct {
	Base64 bool
	Binary bool

	Blake2Key string

	CrcPolynomial string
}

func main() {
	log.SetFlags(0)
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

		// Flags for all hashes.
		cmd.Flags().BoolVarP(&options.Base64, "base64", "A", options.Base64,
			"print hash values encoded as base64")
		cmd.Flags().BoolVarP(&options.Binary, "binary", "b", options.Binary,
			"print hash values directly without encoding")

		// Hash-specific flags.
		switch true {
		case strings.HasPrefix(name, "blake2"):
			cmd.Flags().StringVarP(&options.Blake2Key, "key", "k", options.Blake2Key,
				"hex encoded key for use with blake2 family of size 0-64 bytes")
		case name == "crc32":
			cmd.Flags().StringVar(&options.CrcPolynomial, "polynomial-table",
				"ieee", "polynomial constant for table generation, ieee/castagnoli/koopman")
		case name == "crc64":
			cmd.Flags().StringVar(&options.CrcPolynomial, "polynomial-table",
				"iso", "polynomial constant for table generation, iso/ecma")
		}
		rootCmd.AddCommand(cmd)
	}

	rootCmd.Flags().BoolVarP(&options.Base64, "base64", "A", options.Base64,
		"print hash values encoded as base64")
	rootCmd.Flags().BoolVarP(&options.Binary, "binary", "b", options.Binary,
		"print hash values directly without encoding")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var hashes = map[string]func(*Options) hash.Hash{
	"adler32": func(*Options) hash.Hash { return adler32.New() },
	"crc32": func(o *Options) hash.Hash {
		return crc32.New(crc32table(o.CrcPolynomial))
	},
	"crc64": func(o *Options) hash.Hash {
		return crc64.New(crc64table(o.CrcPolynomial))
	},

	"md4": func(*Options) hash.Hash { return md4.New() },
	"md5": func(*Options) hash.Hash { return md5.New() },

	"sha1":       func(*Options) hash.Hash { return sha1.New() },
	"sha224":     func(*Options) hash.Hash { return sha256.New224() },
	"sha256":     func(*Options) hash.Hash { return sha256.New() },
	"sha384":     func(*Options) hash.Hash { return sha512.New384() },
	"sha512":     func(*Options) hash.Hash { return sha512.New() },
	"sha512/224": func(*Options) hash.Hash { return sha512.New512_224() },
	"sha512/256": func(*Options) hash.Hash { return sha512.New512_256() },
	"sha3-224":   func(*Options) hash.Hash { return sha3.New224() },
	"sha3-256":   func(*Options) hash.Hash { return sha3.New256() },
	"sha3-384":   func(*Options) hash.Hash { return sha3.New384() },
	"sha3-512":   func(*Options) hash.Hash { return sha3.New512() },

	"blake2-256": blakeKey(blake2b.New256),
	"blake2-384": blakeKey(blake2b.New384),
	"blake2-512": blakeKey(blake2b.New512),

	"ripemd160": func(*Options) hash.Hash { return ripemd160.New() },
}

func printHash(name string, hfn func(*Options) hash.Hash, o *Options) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		h := hfn(o)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatalf("FATAL: failed to compute %q hash from stdin: %v", name, err)
		}
		hash := h.Sum(nil)

		switch true {
		case o.Base64 && o.Binary:
			log.Fatalf(`FATAL: conflicting flags "base64" and "binary".`)
		case o.Base64:
			fmt.Println(base64.StdEncoding.EncodeToString(hash))
		case o.Binary:
			if n, err := os.Stdout.Write(hash); err != nil || n != len(hash) {
				log.Fatalf("FATAL: failed to write hash to stdout: %v", err)
			}
		default:
			fmt.Println(hex.EncodeToString(hash))
		}
	}
}

func blakeKey(f func([]byte) (hash.Hash, error)) func(*Options) hash.Hash {
	return func(o *Options) hash.Hash {
		var key []byte = nil
		if o.Blake2Key != "" {
			if k, err := hex.DecodeString(o.Blake2Key); err != nil {
				log.Fatalf("FATAL: invalid hex encoded key: %v.", err)
			} else if len(k) > 64 {
				log.Fatalf("FATAL: key is too long, got %v byte, wanted <= 64.", len(k))
			} else {
				key = k
			}
		}

		h, err := f(key)
		if err != nil {
			log.Fatalf("FATAL: failed to create new blake2 key: %v", err)
		}
		return h
	}
}

func crc32table(s string) *crc32.Table {
	polynomial, ok := map[string]uint32{
		"castagnoli": crc32.Castagnoli,
		"ieee":       crc32.IEEE,
		"koopman":    crc32.Koopman,
	}[s]

	if !ok {
		log.Fatalf("FATAL: invalid crc32 polynomial name %q, try ieee/castagnoli/koopman.", s)
	}
	return crc32.MakeTable(polynomial)
}

func crc64table(s string) *crc64.Table {
	polynomial, ok := map[string]uint64{
		"ecma": crc64.ECMA,
		"iso":  crc64.ISO,
	}[s]

	if !ok {
		log.Fatalf("FATAL: invalid crc64 polynomial name %q, try iso/ecma.", s)
	}
	return crc64.MakeTable(polynomial)
}
