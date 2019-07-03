.PHONY: \
	build \
	install \
	all \
	vendor \
 	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	cov \
	clean

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/future-architect/vuls/config.Version=$(VERSION)' \
    -X 'github.com/future-architect/vuls/config.Revision=build-$(BUILDTIME)_$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go


all: build

build: main.go pretest fmt
	$(GO) build -a -ldflags "$(LDFLAGS)" -o vuls $<

b: 	main.go pretest
	$(GO) build -ldflags "$(LDFLAGS)" -o vuls $<

install: main.go pretest
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	$(GO_OFF) get -u golang.org/x/lint/golint
	golint $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

mlint:
	$(foreach file,$(SRCS),gometalinter $(file) || exit;)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: 
	$(GO) test -cover -v ./... || exit;

unused:
	$(foreach pkg,$(PKGS),unused $(pkg);)

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	echo $(PKGS) | xargs go clean || exit;
	echo $(PKGS) | xargs go clean || exit;

