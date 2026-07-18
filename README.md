# dgst

Compute and print message digest hashes of stdin.

## Usage
```
Print message digest hashes of stdin.

Usage:
  dgst [flags]
  dgst [command]

Available Commands:
  adler32     Digest input using ADLER32
  blake2-256  Digest input using BLAKE2-256
  blake2-384  Digest input using BLAKE2-384
  blake2-512  Digest input using BLAKE2-512
  crc32       Digest input using CRC32
  crc64       Digest input using CRC64
  fnv1-128    Digest input using FNV1-128
  fnv1-32     Digest input using FNV1-32
  fnv1-64     Digest input using FNV1-64
  fnv1a-128   Digest input using FNV1A-128
  fnv1a-32    Digest input using FNV1A-32
  fnv1a-64    Digest input using FNV1A-64
  help        Help about any command
  md4         Digest input using MD4
  md5         Digest input using MD5
  murmur      Digest input using MURMUR
  murmur3     Digest input using MURMUR3
  murmur3-128 Digest input using MURMUR3-128
  murmur3-64  Digest input using MURMUR3-64
  ripemd128   Digest input using RIPEMD128
  ripemd160   Digest input using RIPEMD160
  sha1        Digest input using SHA1
  sha224      Digest input using SHA224
  sha256      Digest input using SHA256
  sha3-224    Digest input using SHA3-224
  sha3-256    Digest input using SHA3-256
  sha3-384    Digest input using SHA3-384
  sha3-512    Digest input using SHA3-512
  sha384      Digest input using SHA384
  sha512      Digest input using SHA512
  sha512/224  Digest input using SHA512/224
  sha512/256  Digest input using SHA512/256
  tiger       Digest input using TIGER
  tiger2      Digest input using TIGER2
  whirlpool   Digest input using WHIRLPOOL

Flags:
  -a, --base64            print hash values encoded as base64
  -b, --binary            print hash values directly without encoding
  -h, --help              help for dgst
  -x, --hex               print hash values encoded as hex (default)
      --hmac-key string   filename containing key for HMAC computation
      --sri               print Subresource Integrity value string
  -v, --version           print the current version

Use "dgst [command] --help" for more information about a command.
```

## Examples
```sh
$ echo -n | dgst md5
d41d8cd98f00b204e9800998ecf8427e
$ echo -n | dgst md5 --binary | xxd
00000000: d41d 8cd9 8f00 b204 e980 0998 ecf8 427e  ..............B~
$ echo -n | dgst md5 --base64
1B2M2Y8AsgTpgAmY7PhCfg==
$ echo -n | dgst blake2-256 --base64
DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g=
$ echo -n | dgst blake2-256 --blake-key=deadbeef --base64
aSYX2bvjUGB+3hPEZrOTwL7m8UR0ESVGP5Zm1z5kh2U=
$ echo OK | dgst crc32 --polynomial-table=castagnoli
d6a6fc12
$ echo -n key > /tmp/hmac.key
$ echo -n 'The quick brown fox jumps over the lazy dog' \
    | dgst sha1 --hmac-key=/tmp/hmac.key
de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
```
