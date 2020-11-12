FROM golang:alpine as builder

RUN apk add --no-cache \
        git \
        make \
        gcc \
        musl-dev

ENV REPOSITORY github.com/future-architect/vuls
COPY . $GOPATH/src/$REPOSITORY
RUN cd $GOPATH/src/$REPOSITORY && make install


FROM alpine:3.11

MAINTAINER hikachan sadayuki-matsuno

ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls

RUN apk add --no-cache \
        openssh-client \
        ca-certificates \
        git \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/vuls /usr/local/bin/

VOLUME ["$WORKDIR", "$LOGDIR"]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["vuls"]
CMD ["--help"]
