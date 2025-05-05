package main

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type Options struct {
	FormatBase64 bool
	FormatBinary bool
	FormatSRI    bool

	SeedUint32 uint32

	Blake2Key string
	HmacKey   string

	Crc32Polynomial string
	Crc64Polynomial string
}

func newDgstCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "dgst",
		Short:             "Print message digest hashes of stdin.",
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
}

var dgstCmd = newDgstCmd()

func main() {
	log.SetFlags(0)
	options := &Options{}

	for name, hfn := range hashes {
		cmd := &cobra.Command{
			Use: name, Aliases: aliases[name],
			Short: fmt.Sprintf("Digest input as %v", strings.ToUpper(name)),
			Run:   printHash(name, hfn, options),
		}

		// Flags for all hashes.
		cmd.Flags().BoolVarP(&options.FormatBase64, "base64", "a", options.FormatBase64,
			"print hash values encoded as base64")
		cmd.Flags().BoolVarP(&options.FormatBinary, "binary", "b", options.FormatBinary,
			"print hash values directly without encoding")
		cmd.Flags().BoolVar(&options.FormatSRI, "sri", options.FormatSRI,
			"print Subresource Integrity value string")
		cmd.Flags().StringVar(&options.HmacKey, "hmac-key", options.HmacKey,
			"secret key for HMAC computation")

		// Hash-specific flags.
		switch true {
		case strings.HasPrefix(name, "blake2"):
			cmd.Flags().StringVar(&options.Blake2Key, "blake-key", options.Blake2Key,
				"hex encoded key for use with blake2 family of size 0-64 bytes")
		case name == "crc32":
			cmd.Flags().StringVar(&options.Crc32Polynomial, "polynomial-table",
				"ieee", "polynomial constant for table generation, ieee/castagnoli/koopman")
		case name == "crc64":
			cmd.Flags().StringVar(&options.Crc64Polynomial, "polynomial-table",
				"iso", "polynomial constant for table generation, iso/ecma")
		case strings.HasPrefix(name, "murmur"): // TODO
			cmd.Flags().Uint32Var(&options.SeedUint32, "seed", 0, "seed value")
		}
		dgstCmd.AddCommand(cmd)
	}

	// Global flags.
	dgstCmd.Flags().BoolVarP(&options.FormatBase64, "base64", "a", options.FormatBase64,
		"print hash values encoded as base64")
	dgstCmd.Flags().BoolVarP(&options.FormatBinary, "binary", "b", options.FormatBinary,
		"print hash values directly without encoding")
	dgstCmd.Flags().BoolVar(&options.FormatSRI, "sri", options.FormatSRI,
		"print Subresource Integrity value string")
	dgstCmd.Flags().StringVar(&options.HmacKey, "hmac-key", options.HmacKey,
		"secret key for HMAC computation")

	if err := dgstCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func printHash(name string, hfn func(*Options) hash.Hash, o *Options) func(*cobra.Command, []string) {
	return func(c *cobra.Command, s []string) {
		var h hash.Hash
		stdin := c.InOrStdin()
		stdout := c.OutOrStdout()

		if o.HmacKey == "" {
			h = hfn(o)
		} else {
			f := func() hash.Hash { return hfn(o) }
			h = hmac.New(f, []byte(o.HmacKey))
		}

		if _, err := io.Copy(h, stdin); err != nil {
			log.Fatalf("FATAL: failed to compute %q hash from stdin: %v", name, err)
		}
		hash := h.Sum(nil)

		formats := getFormats(o)
		switch true {
		case len(formats) > 1:
			log.Fatalf("FATAL: conflicting format flags: %v", quoteFormats(formats))
		case o.FormatBase64:
			fmt.Fprintln(stdout, base64.StdEncoding.EncodeToString(hash))
		case o.FormatBinary:
			if n, err := stdout.Write(hash); err != nil || n != len(hash) {
				log.Fatalf("FATAL: failed to write hash to stdout: %v", err)
			}
		case o.FormatSRI:
			fmt.Fprintln(stdout, name+"-"+base64.StdEncoding.EncodeToString(hash))
		default:
			fmt.Fprintln(stdout, hex.EncodeToString(hash))
		}
	}
}

func getFormats(o *Options) []string {
	selectedFormats := []string{}
	for k, v := range map[string]bool{
		"base64": o.FormatBase64,
		"binary": o.FormatBinary,
		"sri":    o.FormatSRI,
	} {
		if v {
			selectedFormats = append(selectedFormats, k)
		}
	}
	return selectedFormats
}

func quoteFormats(ss []string) string {
	for i, s := range ss {
		ss[i] = fmt.Sprintf(`"--%v"`, s)
	}
	sort.Slice(ss, func(i, j int) bool { return ss[i] < ss[j] })
	return strings.Join(ss, ", ")
}
