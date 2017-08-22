FROM golang:latest

MAINTAINER sadayuki-matsuno

ENV REPOSITORY github.com/kotakanbe/goval-dictionary
ENV LOGDIR /var/log/vuls
ENV WORKDIR /vuls
# goval-dictionary install
RUN git clone https://$REPOSITORY.git $GOPATH/src/$REPOSITORY \
    && cd $GOPATH/src/$REPOSITORY \
    && make install \
    && mkdir -p $LOGDIR

VOLUME [$WORKDIR, $LOGDIR]
WORKDIR $WORKDIR
ENV PWD $WORKDIR

ENTRYPOINT ["goval-dictionary"]
CMD ["--help"]
