VERSION=0.1.0
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION}"
all: check-cert-net

.PHONY: check-cert-net linux check lint

check-cert-net: *.go execpipe/*.go
	go build $(LDFLAGS) -o check-cert-net

linux: *.go execpipe/*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o check-cert-net

check:
	go test -v ./...

lint:
	golangci-lint run ./...