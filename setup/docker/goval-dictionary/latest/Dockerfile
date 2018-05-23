FROM golang:alpine as builder

RUN apk add --no-cache \
        git \
        make \
        gcc \
        musl-dev

ENV REPOSITORY github.com/kotakanbe/goval-dictionary
RUN git clone https://$REPOSITORY.git $GOPATH/src/$REPOSITORY \
    && cd $GOPATH/src/$REPOSITORY \
    && make install


FROM alpine:3.7

MAINTAINER sadayuki-matsuno

ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls

RUN apk add --no-cache ca-certificates \
    && mkdir -p $WORKDIR $LOGDIR

COPY --from=builder /go/bin/goval-dictionary /usr/local/bin/

VOLUME [$WORKDIR, $LOGDIR]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["goval-dictionary"]
CMD ["--help"]
