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

install: ./cmd/vuls/main.go
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/vuls

build-scanner: ./cmd/scanner/main.go 
	$(CGO_UNABLED) build -tags=scanner -a -ldflags "$(LDFLAGS)" -o vuls ./cmd/scanner

install-scanner: ./cmd/scanner/main.go 
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
	gocov test -v ./... | gocov report

clean:
	echo $(PKGS) | xargs go clean || exit;

# trivy-to-vuls
build-trivy-to-vuls: pretest fmt
	$(GO) build -o trivy-to-vuls contrib/trivy/cmd/*.go

# future-vuls
build-future-vuls: pretest fmt
	$(GO) build -o future-vuls contrib/future-vuls/cmd/*.go


# integration-test
BASE_DIR := '${PWD}/integration/results'
# $(shell mkdir -p ${BASE_DIR})
NOW=$(shell date --iso-8601=seconds)
NOW_JSON_DIR := '${BASE_DIR}/$(NOW)'
ONE_SEC_AFTER=$(shell date -d '+1 second' --iso-8601=seconds)
ONE_SEC_AFTER_JSON_DIR := '${BASE_DIR}/$(ONE_SEC_AFTER)'
LIBS := 'gemfile' 'pipfile' 'poetry' 'composer' 'packagelock' 'yarn' 'cargo' 'gomod' 'rails' 'cpe_vendor_product_match'

diff:
	# git clone git@github.com:vulsio/vulsctl.git
	# cd vulsctl/docker
	# ./update-all.sh
	# cd /path/to/vuls
	# vim integration/int-config.toml
	# ln -s vuls vuls.new
	# ln -s oldvuls vuls.old
	# make int
    # (ex. test 10 times: for i in `seq 10`; do make int ARGS=-quiet ; done)
ifneq ($(shell ls -U1 ${BASE_DIR} | wc -l), 0)
	mv ${BASE_DIR} /tmp/${NOW}
endif
	mkdir -p ${NOW_JSON_DIR}
	sleep 1
	./vuls.old scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp ${BASE_DIR}/current/*.json ${NOW_JSON_DIR}
	- cp integration/data/results/*.json ${NOW_JSON_DIR}
	./vuls.old report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-config.toml ${NOW}

	mkdir -p ${ONE_SEC_AFTER_JSON_DIR}
	sleep 1
	./vuls.new scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp ${BASE_DIR}/current/*.json ${ONE_SEC_AFTER_JSON_DIR}
	- cp integration/data/results/*.json ${ONE_SEC_AFTER_JSON_DIR}
	./vuls.new report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-config.toml ${ONE_SEC_AFTER}

	$(call sed-d)
	- diff -c ${NOW_JSON_DIR} ${ONE_SEC_AFTER_JSON_DIR}
	echo "old: ${NOW_JSON_DIR} , new: ${ONE_SEC_AFTER_JSON_DIR}"
	$(call count-cve)

diff-redis:
	# docker network create redis-nw
    # docker run --name redis -d --network redis-nw -p 127.0.0.1:6379:6379 redis
	# git clone git@github.com:vulsio/vulsctl.git
	# cd vulsctl/docker
	# ./update-all-redis.sh
	# (or export DOCKER_NETWORK=redis-nw; cd /home/ubuntu/vulsctl/docker; ./update-all.sh --dbtype redis --dbpath "redis://redis/0")
	# vim integration/int-redis-config.toml
	# ln -s vuls vuls.new
	# ln -s oldvuls vuls.old
	# make int-redis
ifneq ($(shell ls -U1 ${BASE_DIR} | wc -l), 0)
	mv ${BASE_DIR} /tmp/${NOW}
endif
	mkdir -p ${NOW_JSON_DIR}
	sleep 1
	./vuls.old scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp -f ${BASE_DIR}/current/*.json ${NOW_JSON_DIR}
	- cp integration/data/results/*.json ${NOW_JSON_DIR}
	./vuls.old report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-redis-config.toml ${NOW}

	mkdir -p ${ONE_SEC_AFTER_JSON_DIR}
	sleep 1
	./vuls.new scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp -f ${BASE_DIR}/current/*.json ${ONE_SEC_AFTER_JSON_DIR}
	- cp integration/data/results/*.json ${ONE_SEC_AFTER_JSON_DIR}
	./vuls.new report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-redis-config.toml ${ONE_SEC_AFTER}

	$(call sed-d)
	- diff -c ${NOW_JSON_DIR} ${ONE_SEC_AFTER_JSON_DIR}
	echo "old: ${NOW_JSON_DIR} , new: ${ONE_SEC_AFTER_JSON_DIR}"
	$(call count-cve)

diff-rdb-redis:
ifneq ($(shell ls -U1 ${BASE_DIR} | wc -l), 0)
	mv ${BASE_DIR} /tmp/${NOW}
endif
	mkdir -p ${NOW_JSON_DIR}
	sleep 1
	# new vs new
	./vuls.new scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp -f ${BASE_DIR}/current/*.json ${NOW_JSON_DIR}
	cp integration/data/results/*.json ${NOW_JSON_DIR}
	./vuls.new report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-config.toml ${NOW}

	mkdir -p ${ONE_SEC_AFTER_JSON_DIR}
	sleep 1
	./vuls.new scan -config=./integration/int-config.toml --results-dir=${BASE_DIR} ${LIBS}
	cp -f ${BASE_DIR}/current/*.json ${ONE_SEC_AFTER_JSON_DIR}
	cp integration/data/results/*.json ${ONE_SEC_AFTER_JSON_DIR}
	./vuls.new report --format-json --refresh-cve --results-dir=${BASE_DIR} -config=./integration/int-redis-config.toml ${ONE_SEC_AFTER}

	$(call sed-d)
	- diff -c ${NOW_JSON_DIR} ${ONE_SEC_AFTER_JSON_DIR}
	echo "old: ${NOW_JSON_DIR} , new: ${ONE_SEC_AFTER_JSON_DIR}"
	$(call count-cve)

head= $(shell git rev-parse HEAD)
prev= $(shell git rev-parse HEAD^)
branch=$(shell git rev-parse --abbrev-ref HEAD)
build-integration:
	git stash

	# buld HEAD
	git checkout ${head}
	make build
	mv -f ./vuls ./vuls.${head}

	# HEAD^
	git checkout ${prev}
	make build
	mv -f ./vuls ./vuls.${prev}

	# master
	git checkout master
	make build
	mv -f ./vuls ./vuls.master

	# working tree
	git checkout ${branch}
	git stash apply stash@\{0\}
	make build

	# for integration testing, vuls.new and vuls.old needed.
	# ex)
	# $ ln -s ./vuls ./vuls.new
	# $ ln -s ./vuls.${head} ./vuls.old
	# or 
	# $ ln -s ./vuls.${prev} ./vuls.old
	# then
	# $ make diff
	# $ make diff-redis
	# $ make diff-rdb-redis


define sed-d
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/scannedAt/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/scannedAt/d' {} \;
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/reportedAt/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/reportedAt/d' {} \;
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/"Type":/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/"Type":/d' {} \;
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/"SQLite3Path":/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/"SQLite3Path":/d' {} \;
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/reportedRevision/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/reportedRevision/d' {} \;
	find ${NOW_JSON_DIR} -type f -exec sed -i -e '/scannedRevision/d' {} \;
	find ${ONE_SEC_AFTER_JSON_DIR} -type f -exec sed -i -e '/scannedRevision/d' {} \;
endef

define count-cve
	for jsonfile in ${NOW_JSON_DIR}/*.json ;  do \
		echo $$jsonfile; cat $$jsonfile | jq ".scannedCves | length" ; \
	done
	for jsonfile in ${ONE_SEC_AFTER_JSON_DIR}/*.json ;  do \
		echo $$jsonfile; cat $$jsonfile | jq ".scannedCves | length" ; \
	done
endef