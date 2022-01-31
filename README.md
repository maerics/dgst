# dgst

Compute and print message digest hash values of stdin.

## Usage
```
Compute and print message digest hash values of stdin.

Usage:
  dgst [command]

Available Commands:
  blake2-256  Compute and print the "blake2-256" digest of stdin.
  blake2-384  Compute and print the "blake2-384" digest of stdin.
  blake2-512  Compute and print the "blake2-512" digest of stdin.
  help        Help about any command
  md4         Compute and print the "md4" digest of stdin.
  md5         Compute and print the "md5" digest of stdin.
  ripemd160   Compute and print the "ripemd160" digest of stdin.
  sha1        Compute and print the "sha1" digest of stdin.
  sha256      Compute and print the "sha256" digest of stdin.
  sha3-224    Compute and print the "sha3-224" digest of stdin.
  sha3-256    Compute and print the "sha3-256" digest of stdin.
  sha3-384    Compute and print the "sha3-384" digest of stdin.
  sha3-512    Compute and print the "sha3-512" digest of stdin.
  sha384      Compute and print the "sha384" digest of stdin.
  sha512      Compute and print the "sha512" digest of stdin.

Flags:
  -A, --base64   print hash values encoded as base64
  -b, --binary   print hash values directly without encoding
  -h, --help     help for dgst

Use "dgst [command] --help" for more information about a command.
```

## Examples
```
$ echo -n | dgst md5
d41d8cd98f00b204e9800998ecf8427e
$ echo -n | dgst md5 --binary | xxd
00000000: d41d 8cd9 8f00 b204 e980 0998 ecf8 427e  ..............B~
$ echo -n | dgst blake2-256 --base64
1B2M2Y8AsgTpgAmY7PhCfg==
$ echo -n | dgst blake2-256 --base64
DldRwCblQ7Loqy6wYJnaodHl30d3j3eH+qtFzfEv46g=
$ echo -n | dgst blake2-256 --base64 --key=deadbeef
aSYX2bvjUGB+3hPEZrOTwL7m8UR0ESVGP5Zm1z5kh2U=
```
