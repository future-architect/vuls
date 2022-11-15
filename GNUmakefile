VERSION := $(shell git describe --tags --abbrev=0)
ifeq ($(VERSION), )
	VERSION := $(shell git rev-parse --abbrev-ref HEAD)
endif
ifeq ($(shell git rev-parse --abbrev-ref HEAD), nightly)
	VERSION := nightly
endif
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -ldflags "-s -w -X=github.com/future-architect/vuls/pkg/cmd/version.Version=$(VERSION) -X=github.com/future-architect/vuls/pkg/cmd/version.Revision=$(REVISION)"

GOPATH := $(shell go env GOPATH)
GOBIN := $(GOPATH)/bin

$(GOBIN)/golangci-lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

.PHONY: build
build: 
	go build $(LDFLAGS) ./cmd/vuls

.PHONY: install
install: 
	go install $(LDFLAGS) ./cmd/vuls

.PHONY: test
test: pretest
	go test -race ./...

.PHONY: pretest
pretest: lint vet fmtcheck

.PHONY: lint
lint: $(GOBIN)/golangci-lint
	golangci-lint run

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmtcheck
fmtcheck:
	gofmt -s -d .