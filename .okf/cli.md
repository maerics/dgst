---
type: interface
title: dgst command structure
description: Top-level command, global flags, and output formats for the dgst CLI.
resource: ./main.go
tags: [cli, flags]
timestamp: 2026-07-17
---

# dgst command structure

Built with `github.com/spf13/cobra`. Root command `dgst` has one
subcommand per hash algorithm (see [hashes.md](./hashes.md)); each
subcommand takes no positional args and reads hash input from stdin.

Default usage (no args, `-h`/`--help`) prints the help message.

## Global flags

Available on the root command and every hash subcommand:

| Flag | Short | Description |
|---|---|---|
| `--base64` | `-a` | print hash value base64-encoded |
| `--binary` | `-b` | print hash value raw, no encoding |
| `--sri` | | print as a Subresource Integrity string (`<algo>-<base64>`) |
| `--hex` | `-x` | print hash value lowercase hex-encoded (same as the default) |
| `--hmac-key <file>` | | compute HMAC using the key read from `<file>`, instead of a plain digest |
| `--version` | `-v` | print version/commit/build-timestamp (root command only) |

Default output (no format flag) is lowercase hex; `--hex`/`-x` makes
that explicit.

At most one of `--base64` / `--binary` / `--sri` / `--hex` may be set;
combining two is a fatal error (`getFormats`/`quoteFormats` in
`main.go`).

`--sri` accepts any hash algorithm, but the W3C SRI spec only
recognizes `sha256`/`sha384`/`sha512` as valid hash-algo tokens
(https://www.w3.org/TR/SRI/#hash-functions). Using `--sri` with any
other algorithm (e.g. `md5`, `sha1`, `blake2-256`) prints a `WARNING:`
line to stderr but still emits the SRI string on stdout
(`sriStandardAlgorithms` in `main.go`).

## Version info

`--version` prints `getVersionString()`, built from `version`, `commit`,
`date` — linked in via `-ldflags` at build time (see
[release.md](./release.md)). Unset (`go run`/`go test` builds) prints
`(unknown)`.
