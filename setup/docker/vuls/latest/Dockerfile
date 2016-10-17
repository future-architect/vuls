FROM golang:latest

MAINTAINER hikachan sadayuki-matsuno

ENV REPOSITORY github.com/future-architect/vuls
ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls
# go-cve-dictionary install
RUN git clone https://$REPOSITORY.git $GOPATH/src/$REPOSITORY \
    && cd $GOPATH/src/$REPOSITORY \
    && make install \
    && mkdir -p $LOGDIR

VOLUME [$WORKDIR, $LOGDIR]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["vuls"]
CMD ["--help"]
