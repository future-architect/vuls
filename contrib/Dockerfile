FROM golang:alpine as builder

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
        make build-future-vuls && mv future-vuls $GOPATH/bin

FROM alpine:3.15

ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls

RUN apk add --no-cache \
        openssh-client \
        ca-certificates \
        git \
        nmap \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/vuls /go/bin/trivy-to-vuls /go/bin/future-vuls /usr/local/bin/
COPY --from=aquasec/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD $WORKDIR