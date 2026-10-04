# Makefile
#
# `make check` is what CI runs and what you should run before opening a PR.

GO      ?= go
BINARY  := sixi-scanner
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build check test race lint fmt vet clean install demo

all: check

## build: compile the binary into the working tree
build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sixi-scanner

## test: run the test suite
test:
	$(GO) test ./...

## race: run the suite under the race detector
# The engine probes techniques concurrently, so anything touching findings or
# attempt recording has to hold up here.
race:
	$(GO) test -race ./...

## lint: fail if anything is unformatted
lint:
	@out=$$(gofmt -l . ); \
	if [ -n "$$out" ]; then \
		echo "gofmt needed on:"; echo "$$out"; exit 1; \
	fi

## vet: run go vet
vet:
	$(GO) vet ./...

## check: everything CI runs
check: lint vet test build

## install: install to GOBIN
install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/sixi-scanner

## demo: scan the in-process echo target and print a Markdown report
## No network, no credentials — the fastest way to see what the output looks like.
demo: build
	./$(BINARY) scan --target echo --format markdown

## clean: remove build output
clean:
	rm -f $(BINARY)
