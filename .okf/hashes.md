---
type: reference
title: Supported hash algorithms
description: Every hash subcommand dgst registers, its aliases, and algorithm-specific flags.
resource: ./hashes.go
tags: [cli, hashing]
timestamp: 2026-07-17
---

# Supported hash algorithms

Registered in the `hashes` map in `hashes.go`; one cobra subcommand is
generated per entry. Aliases come from the `aliases` map.

| Command | Aliases | Notes |
|---|---|---|
| `adler32` | | stdlib `hash/adler32` |
| `crc32` | | `--polynomial-table ieee\|castagnoli\|koopman` (default `ieee`) |
| `crc64` | | `--polynomial-table iso\|ecma` (default `iso`) |
| `md4` | | `golang.org/x/crypto/md4` |
| `md5` | | stdlib |
| `sha1` | `sha-1` | stdlib |
| `sha224` | `sha-224` | stdlib (`sha256.New224`) |
| `sha256` | `sha-256` | stdlib |
| `sha384` | `sha-384` | stdlib (`sha512.New384`) |
| `sha512` | `sha-512` | stdlib |
| `sha512/224` | `sha-512/224` | stdlib |
| `sha512/256` | `sha-512/256` | stdlib |
| `sha3-224` | `sha-3-224` | `golang.org/x/crypto/sha3` |
| `sha3-256` | `sha-3-256` | " |
| `sha3-384` | `sha-3-384` | " |
| `sha3-512` | `sha-3-512` | " |
| `fnv1-32` | `fnv-1-32` | stdlib `hash/fnv` |
| `fnv1a-32` | `fnv-1a-32` | " |
| `fnv1-64` | `fnv-1-64` | " |
| `fnv1a-64` | `fnv-1a-64` | " |
| `fnv1-128` | `fnv-1-128` | " |
| `fnv1a-128` | `fnv-1a-128` | " |
| `blake2-256` | | `--blake-key <hex>`, 0-64 bytes |
| `blake2-384` | | " |
| `blake2-512` | | " |
| `ripemd128` | `ripemd-128` | `github.com/zhimoe/ripemd128` |
| `ripemd160` | `ripemd-160` | `golang.org/x/crypto/ripemd160` |
| `murmur` | `murmur2` | `--seed <uint32>`, default `0x9747b28c` |
| `murmur3` | | `--seed <uint32>`, default `0` |
| `murmur3-64` | | " |
| `murmur3-128` | | " |
| `tiger` | | `github.com/cxmcc/tiger` |
| `tiger2` | | " |
| `whirlpool` | | `github.com/jzelinskie/whirlpool` |

Any algorithm command also accepts the global flags in
[cli.md](./cli.md) (`--base64`, `--binary`, `--sri`, `--hmac-key`).

## Notes

- `murmur` (murmur2) is the only algorithm whose default seed is
  non-zero (`0x9747b28c`); `--seed` explicitly set (tracked via
  `SeedSet`) overrides the default for any murmur family member.
- `--hmac-key` wraps any hash constructor in `crypto/hmac.New`, so HMAC
  works uniformly across every algorithm above.
