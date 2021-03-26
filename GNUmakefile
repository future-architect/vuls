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
CGO_UNABLED := CGO_ENABLED=0 go
GO_OFF := GO111MODULE=off go


all: build

build: ./cmd/vuls/main.go pretest fmt
	$(GO) build -a -ldflags "$(LDFLAGS)" -o vuls ./cmd/vuls

b: ./cmd/vuls/main.go 
	$(GO) build -a -ldflags "$(LDFLAGS)" -o vuls ./cmd/vuls

install: ./cmd/vuls/main.go pretest fmt
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/vuls

build-scanner: ./cmd/scanner/main.go pretest fmt
	$(CGO_UNABLED) build -tags=scanner -a -ldflags "$(LDFLAGS)" -o vuls ./cmd/scanner

install-scanner: ./cmd/scanner/main.go pretest fmt
	$(CGO_UNABLED) install -tags=scanner -ldflags "$(LDFLAGS)" ./cmd/scanner

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

# trivy-to-vuls
build-trivy-to-vuls: pretest fmt
	$(GO) build -o trivy-to-vuls contrib/trivy/cmd/*.go

# future-vuls
build-future-vuls: pretest fmt
	$(GO) build -o future-vuls contrib/future-vuls/cmd/*.go


# integration-test
# $ git clone git@github.com:vulsio/vulsctl.git
# $ cd vulsctl/docker
# $ ./update-all.sh
# $ cd /path/to/vuls
# $ vim integration/config.toml
# $ ln -s vuls vuls.new
# $ ln -s oldvuls vuls.old
# $ make int
# $ make int-redis
BASE_DIR := '${PWD}/integration/results'
NOW=$(shell date --iso-8601=seconds)
NOW_JSON_DIR := '${BASE_DIR}/$(NOW)'
ONE_SEC=$(shell date -d '+1 second' --iso-8601=seconds)
ONE_SEC_JSON_DIR := '${BASE_DIR}/$(ONE_SEC)'

int:
	#cd /home/ubuntu/vulsctl/docker; ./update-all.sh
	mkdir -p ${NOW_JSON_DIR}
	cp integration/data/*.json ${NOW_JSON_DIR}
	./vuls.old report --quiet --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-config.toml 
	mkdir -p ${ONE_SEC_JSON_DIR}
	cp integration/data/*.json ${ONE_SEC_JSON_DIR}
	./vuls.new report --quiet --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-config.toml 
	diff ${NOW_JSON_DIR} ${ONE_SEC_JSON_DIR}


int-redis:
	#export DOCKER_NETWORK=redis-nw
	#cd /home/ubuntu/vulsctl/docker; ./update-all.sh --dbtype redis --dbpath "redis://redis/0"
	#unset DOCKER_NETWORK
	mkdir -p ${NOW_JSON_DIR}
	cp integration/data/*.json ${NOW_JSON_DIR}
	./vuls.old report --quiet --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-redis-config.toml 
	mkdir -p ${ONE_SEC_JSON_DIR}
	cp integration/data/*.json ${ONE_SEC_JSON_DIR}
	./vuls.new report --quiet --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-redis-config.toml 
	diff ${NOW_JSON_DIR} ${ONE_SEC_JSON_DIR}


head= $(shell git rev-parse HEAD)
prev= $(shell git rev-parse HEAD^)
branch=$(shell git rev-parse --abbrev-ref HEAD)
build-int:
	git stash

	# buld HEAD
	git checkout ${head}
	make build
	mv -f ./vuls ./vuls.${head}

	# HEAD^
	git checkout ${prev}
	make build
	mv -f ./vuls ./vuls.${prev}

	git checkout ${branch}
	git stash apply stash@\{0\}

	# buld working tree
	make build

	# for integration testing, 
	# $ ln -s ./vuls ./vuls.new
	# $ ln -s ./vuls.${prev} ./vuls.old
	# $ make int 
	# $ make int-redis