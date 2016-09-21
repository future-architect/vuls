FROM golang:1.7.1

MAINTAINER hikachan sadayuki-matsuno

# glide install
ENV GLIDE_VERSION 0.12.2
ENV GLIDE_DOWNLOAD_URL https://github.com/Masterminds/glide/releases/download/v$GLIDE_VERSION/glide-v$GLIDE_VERSION-linux-amd64.tar.gz
RUN curl -fsSL "$GLIDE_DOWNLOAD_URL" -o glide.tar.gz \
    && mkdir /usr/local/glide \
    && tar -C /usr/local/glide -xzf glide.tar.gz \
    && ln -s /usr/local/glide/linux-amd64/glide /usr/local/bin/ \
    && rm glide.tar.gz
