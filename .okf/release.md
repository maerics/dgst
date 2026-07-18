---
type: process
title: Build and release
description: How dgst is built, versioned, and released via goreleaser to the maerics/homebrew-datautils tap.
resource: ./Makefile
tags: [release, build, goreleaser]
timestamp: 2026-07-17
---

# Build and release

## Local build

`make build` compiles `./dgst`, injecting version info via `-ldflags`:
- `main.version` from `git describe --exact-match --tags`
- `main.commit` from `git rev-parse head`
- `main.date` (UTC build timestamp)

Read back by `getVersionString()` in `main.go` for `dgst --version`.

## Makefile targets

| Target | Purpose |
|---|---|
| `test` | `go test ./...` (default) |
| `build` | build `./dgst` with version ldflags |
| `release-check` | `goreleaser check` |
| `local-release` | snapshot release via goreleaser (no publish) |
| `release` | full goreleaser release; requires clean working tree (`ensure-no-local-changes`) |
| `clean` | remove `./dgst` and `./dist` |

## goreleaser (`.goreleaser.yaml`)

- Builds for linux/windows/darwin, `CGO_ENABLED=0`.
- Archives as `.tar.gz` (`.zip` on windows).
- Publishes a Homebrew formula to `maerics/homebrew-datautils` (tap
  repo), authenticated via `GITHUB_TOKEN` env var.
