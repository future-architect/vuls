FROM vuls/vuls-base:latest

MAINTAINER hikachan sadayuki-matsuno

ENV REPOSITORY github.com/future-architect/vuls
ENV WORKDIR /vuls
# go-cve-dictionary install
RUN git clone https://$REPOSITORY.git $GOPATH/src/$REPOSITORY \
    && cd $GOPATH/src/$REPOSITORY \
    && glide install \
    && go build \
    && mv $GOPATH/src/$REPOSITORY/vuls /usr/local/bin \
    && mkdir -p /var/log/vuls \
    && chmod +x /usr/local/bin/vuls

VOLUME $WORKDIR
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["vuls"]
CMD ["--help"]
