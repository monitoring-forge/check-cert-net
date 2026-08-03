VERSION=0.1.0
GITCOMMIT?=$(shell git describe --dirty --always)
LDFLAGS=-ldflags "-w -s -X main.version=${VERSION} -X main.commit=${GITCOMMIT}"

all: check-cert-net

check-cert-net: *.go execpipe/*.go
	go build $(LDFLAGS) -o check-cert-net

linux: *.go execpipe/*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o check-cert-net

check:
	go test -v ./...

lint:
	golangci-lint run ./...