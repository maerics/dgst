package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

type Options struct {
	FormatBase64 bool
	FormatBinary bool

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
			Use: name, Aliases: aliases[name],
			Short: fmt.Sprintf("Compute and print the %q digest of stdin.", name),
			Run:   printHash(name, hfn, options),
		}

		// Flags for all hashes.
		cmd.Flags().BoolVarP(&options.FormatBase64, "base64", "A", options.FormatBase64,
			"print hash values encoded as base64")
		cmd.Flags().BoolVarP(&options.FormatBinary, "binary", "b", options.FormatBinary,
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

	// Global flags.
	rootCmd.Flags().BoolVarP(&options.FormatBase64, "base64", "A", options.FormatBase64,
		"print hash values encoded as base64")
	rootCmd.Flags().BoolVarP(&options.FormatBinary, "binary", "b", options.FormatBinary,
		"print hash values directly without encoding")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func printHash(name string, hfn func(*Options) hash.Hash, o *Options) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		h := hfn(o)
		if _, err := io.Copy(h, os.Stdin); err != nil {
			log.Fatalf("FATAL: failed to compute %q hash from stdin: %v", name, err)
		}
		hash := h.Sum(nil)

		switch true {
		case o.FormatBase64 && o.FormatBinary:
			log.Fatalf(`FATAL: conflicting flags "base64" and "binary".`)
		case o.FormatBase64:
			fmt.Println(base64.StdEncoding.EncodeToString(hash))
		case o.FormatBinary:
			if n, err := os.Stdout.Write(hash); err != nil || n != len(hash) {
				log.Fatalf("FATAL: failed to write hash to stdout: %v", err)
			}
		default:
			fmt.Println(hex.EncodeToString(hash))
		}
	}
}
