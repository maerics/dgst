# Log

## 2026-07-17

**Initialization**: bootstrapped bundle from repo state (`main.go`,
`hashes.go`, `Makefile`, `.goreleaser.yaml`) at commit `d1cb318`. Covers
CLI structure, supported hash algorithms, and the build/release process.

**Update**: added `--hex`/`-x` format flag to [cli.md](./cli.md) — an
explicit selector for the previously-implicit-only default hex output;
now participates in the format-flag conflict check.

**Update**: documented that `--sri` warns to stderr when used with a
non-W3C-standard hash algorithm (only `sha256`/`sha384`/`sha512` are
spec-valid), while still printing the SRI string on stdout — see
[cli.md](./cli.md).
