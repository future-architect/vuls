FROM golang:alpine@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd as builder

RUN apk add --no-cache \
        git \
        make \
        gcc \
        musl-dev

ENV REPOSITORY github.com/future-architect/vuls
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && \
        make build-scanner && mv vuls $GOPATH/bin && \
        make build-trivy-to-vuls && mv trivy-to-vuls $GOPATH/bin && \
        make build-future-vuls && mv future-vuls $GOPATH/bin && \
        make build-snmp2cpe && mv snmp2cpe $GOPATH/bin

FROM alpine:3.22@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1

ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls

RUN apk add --no-cache \
        openssh-client \
        ca-certificates \
        git \
        nmap \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/vuls /go/bin/trivy-to-vuls /go/bin/future-vuls /go/bin/snmp2cpe /usr/local/bin/
COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD $WORKDIR