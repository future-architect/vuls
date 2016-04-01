.PHONY: \
	all \
	vendor \
	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	integration \
	cov \
	clean

SRCS = $(shell git ls-files '*.go')
PKGS = ./. ./db ./config ./models ./report ./cveapi ./scan ./util ./commands

all: test

vendor:
	@ go get -v github.com/mjibson/party
	party -d external -c -u

lint:
	@ go get -v github.com/golang/lint/golint
	$(foreach file,$(SRCS),golint $(file) || exit;)

vet:
	@-go get -v golang.org/x/tools/cmd/vet
	$(foreach pkg,$(PKGS),go vet $(pkg);)

fmt:
	gofmt -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(foreach pkg,$(PKGS),go test -v $(pkg) || exit;)

unused :
	$(foreach pkg,$(PKGS),unused $(pkg);)

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

