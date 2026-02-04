FROM golang:alpine@sha256:ac09a5f469f307e5da71e766b0bd59c9c49ea460a528cc3e6686513d64a6f1fb AS builder

RUN apk add --no-cache \
        git \
        make \
        gcc \
        musl-dev

ENV REPOSITORY=github.com/future-architect/vuls
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && make install

FROM alpine:3.22@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412

ENV LOGDIR=/var/log/vuls
ENV WORKDIR=/vuls

RUN apk add --no-cache \
        openssh-client \
        ca-certificates \
        git \
        nmap \
        && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/vuls /usr/local/bin/

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD=$WORKDIR

ENTRYPOINT ["vuls"]
CMD ["--help"]
