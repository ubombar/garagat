VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint bench cross integration docker clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/garagat ./cmd/garagat

test:
	go test -race ./...

lint:
	go vet ./...
	go vet -tags integration ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

bench:
	go test -run '^$$' -bench . -benchmem .

cross:
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 freebsd/amd64; do \
		echo "build $$target"; \
		CGO_ENABLED=0 GOOS=$${target%/*} GOARCH=$${target#*/} go build -o /dev/null ./... || exit 1; \
	done

# Runs the real-network tests as root in a Linux container.
integration:
	docker run --rm -v "$(CURDIR)":/src -w /src golang:1.26 sh -c "apt-get -qq update && apt-get -qq install -y iputils-ping >/dev/null && go test -count=1 -tags integration -v -run Integration ./link/ ./prober/"

docker:
	docker build -t garagat .

clean:
	rm -rf bin
