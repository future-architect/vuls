.PHONY: \
	dep \
	depup \
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
PKGS = ./. ./cache ./commands ./config ./models ./oval ./report ./scan ./util 
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'main.version=$(VERSION)' \
	-X 'main.revision=$(REVISION)'

all: dep build test

dep:
	go get -u github.com/golang/dep/...
	dep ensure

depup:
	go get -u github.com/golang/dep/...
	dep ensure -update

build: main.go dep
	go build -ldflags "$(LDFLAGS)" -o vuls $<

install: main.go dep
	go install -ldflags "$(LDFLAGS)"


lint:
	@ go get -v github.com/golang/lint/golint
	$(foreach file,$(SRCS),golint $(file) || exit;)

vet:
	#  @-go get -v golang.org/x/tools/cmd/vet
	echo $(PKGS) | xargs go vet || exit;

fmt:
	gofmt -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	go install
	echo $(PKGS) | xargs go test -cover -v || exit;

unused :
	$(foreach pkg,$(PKGS),unused $(pkg);)

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	echo $(PKGS) | xargs go clean || exit;

