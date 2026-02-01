FROM golang:alpine@sha256:98e6cffc31ccc44c7c15d83df1d69891efee8115a5bb7ede2bf30a38af3e3c92 as builder

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

FROM alpine:3.22@sha256:55ae5d250caebc548793f321534bc6a8ef1d116f334f18f4ada1b2daad3251b2

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