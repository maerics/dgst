package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"log"

	"github.com/aviddiviner/go-murmur"
	"github.com/cxmcc/tiger"
	"github.com/jzelinskie/whirlpool"
	"github.com/twmb/murmur3"
	"github.com/zhimoe/ripemd128"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

const murmur2seed uint32 = 0x9747b28c

var hashes = map[string]func(*Options) hash.Hash{
	"adler32": func(*Options) hash.Hash { return adler32.New() },
	"crc32":   func(o *Options) hash.Hash { return crc32.New(crc32table(o.Crc32Polynomial)) },
	"crc64":   func(o *Options) hash.Hash { return crc64.New(crc64table(o.Crc64Polynomial)) },

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

	"fnv1-32":   func(o *Options) hash.Hash { return fnv.New32() },
	"fnv1a-32":  func(o *Options) hash.Hash { return fnv.New32a() },
	"fnv1-64":   func(o *Options) hash.Hash { return fnv.New64() },
	"fnv1a-64":  func(o *Options) hash.Hash { return fnv.New64a() },
	"fnv1-128":  func(o *Options) hash.Hash { return fnv.New128() },
	"fnv1a-128": func(o *Options) hash.Hash { return fnv.New128a() },

	"blake2-256": blakeKey(blake2b.New256),
	"blake2-384": blakeKey(blake2b.New384),
	"blake2-512": blakeKey(blake2b.New512),

	"ripemd128": func(*Options) hash.Hash { return ripemd128.New() },
	"ripemd160": func(*Options) hash.Hash { return ripemd160.New() },

	"murmur":      func(o *Options) hash.Hash { return murmur.New32(murmur2seed) },
	"murmur3":     func(o *Options) hash.Hash { return murmur3.New32() },
	"murmur3-64":  func(o *Options) hash.Hash { return murmur3.New64() },
	"murmur3-128": func(o *Options) hash.Hash { return murmur3.New128() },

	"tiger":     func(o *Options) hash.Hash { return tiger.New() },
	"tiger2":    func(o *Options) hash.Hash { return tiger.New2() },
	"whirlpool": func(o *Options) hash.Hash { return whirlpool.New() },
}

var aliases = map[string][]string{
	"ripemd128": {"ripemd-128"},
	"ripemd160": {"ripemd-160"},

	"sha1":       {"sha-1"},
	"sha224":     {"sha-224"},
	"sha256":     {"sha-256"},
	"sha384":     {"sha-384"},
	"sha512":     {"sha-512"},
	"sha512/224": {"sha-512/224"},
	"sha512/256": {"sha-512/256"},
	"sha3-224":   {"sha-3-224"},
	"sha3-256":   {"sha-3-256"},
	"sha3-384":   {"sha-3-384"},
	"sha3-512":   {"sha-3-512"},

	"fnv1-32":   {"fnv-1-32"},
	"fnv1a-32":  {"fnv-1a-32"},
	"fnv1-64":   {"fnv-1-64"},
	"fnv1a-64":  {"fnv-1a-64"},
	"fnv1-128":  {"fnv-1-128"},
	"fnv1a-128": {"fnv-1a-128"},

	"murmur": {"murmur2"},
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
