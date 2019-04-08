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
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
BUILDTIME := $(shell date "+%Y%m%d_%H%M%S")
LDFLAGS := -X 'github.com/future-architect/vuls/config.Version=$(VERSION)' \
    -X 'github.com/future-architect/vuls/config.Revision=build-$(BUILDTIME)_$(REVISION)'

all: dep build

dep:
	go get -u github.com/golang/dep/...
	dep ensure -v

depup:
	go get -u github.com/golang/dep/...
	dep ensure -update -v

build: main.go dep pretest
	go build -a -ldflags "$(LDFLAGS)" -o vuls $<

b: 	main.go dep pretest
	go build -ldflags "$(LDFLAGS)" -o vuls $<

install: main.go dep pretest
	go install -ldflags "$(LDFLAGS)"


lint:
	@ go get -v golang.org/x/lint/golint
	golint $(PKGS)

vet:
	#  @-go get -v golang.org/x/tools/cmd/vet
	go vet ./... || exit;

fmt:
	gofmt -s -w $(SRCS)

mlint:
	$(foreach file,$(SRCS),gometalinter $(file) || exit;)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: 
	echo $(PKGS) | xargs go test -cover -v || exit;

unused:
	$(foreach pkg,$(PKGS),unused $(pkg);)

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	echo $(PKGS) | xargs go clean || exit;

