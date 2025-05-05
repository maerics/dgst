test:
	go test ./...

BUILD_VERSION = $(shell git describe --exact-match --tags)
BUILD_COMMIT = $(shell git rev-parse head)
BUILD_TIMESTAMP = $(shell date -z zulu +'%Y-%m-%dT%H:%M:%SZ')
build:
	go build \
			-ldflags " \
				-X 'main.version=$(BUILD_VERSION)' \
				-X 'main.commit=$(BUILD_COMMIT)' \
				-X 'main.date=$(BUILD_TIMESTAMP)' \
			" \
		 -o ./dgst *.go

release-check:
	goreleaser check

local-release: release-check clean
	goreleaser release --snapshot --clean

ensure-no-local-changes:
	@if [ "$(shell git status -s)" != "" ]; then \
		git status -s; \
		echo "\nFATAL: refusing to release with local changes; see git status."; \
		exit 1; \
	fi

release: ensure-no-local-changes clean
	goreleaser release

clean:
	rm -rf ./dgst ./dist
