FROM alpine:3.6

MAINTAINER hikachan sadayuki-matsuno usiusi360

VOLUME /vuls

RUN apk --no-cache add git \
   && git clone https://github.com/usiusi360/vulsrepo.git

RUN cd /vulsrepo/server \
   && sed -i -e 's/\/home\/vuls-user//g' vulsrepo-config.toml \
   && sed -i -e 's/\/opt//g' vulsrepo-config.toml \
   && mkdir /lib64 \
   && ln -s /lib/ld-musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2

EXPOSE 5111
CMD ["/vulsrepo/server/vulsrepo-server"]
