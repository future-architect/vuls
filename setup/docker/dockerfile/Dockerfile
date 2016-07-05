FROM buildpack-deps:jessie-scm

# golang Install
RUN apt-get update && apt-get install -y --no-install-recommends \
        g++ \
        gcc \
        libc6-dev \
        make \
        curl \
    && rm -rf /var/lib/apt/lists/*

ENV GOLANG_VERSION 1.6.2
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 e40c36ae71756198478624ed1bb4ce17597b3c19d243f3f0899bb5740d56212a

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
    && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf golang.tar.gz \
    && rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# glide install
ENV GLIDE_VERSION 0.10.2
ENV GLIDE_DOWNLOAD_URL https://github.com/Masterminds/glide/releases/download/$GLIDE_VERSION/glide-$GLIDE_VERSION-linux-amd64.tar.gz
RUN curl -fsSL "$GLIDE_DOWNLOAD_URL" -o glide.tar.gz \
    && mkdir /usr/local/glide \
    && tar -C /usr/local/glide -xzf glide.tar.gz \
    && ln -s /usr/local/glide/linux-amd64/glide /usr/local/bin/ \
    && rm glide.tar.gz

# nginx Install
RUN apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62 \
    && echo "deb http://nginx.org/packages/mainline/debian/ jessie nginx" >> /etc/apt/sources.list \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
                        ca-certificates \
                        nginx \
                        nginx-module-xslt \
                        nginx-module-geoip \
                        nginx-module-image-filter \
                        nginx-module-perl \
                        nginx-module-njs \
                        gettext-base \
                        wget \
                        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN ln -sf /dev/stdout /var/log/nginx/access.log \
        && ln -sf /dev/stderr /var/log/nginx/error.log

COPY nginx.conf /etc/nginx/nginx.conf

#Vuls Install
ENV VULS_ROOT /opt/vuls
RUN mkdir -p /var/log/vuls ${VULS_ROOT}/conf /root/.ssh/
RUN chmod 700 -R /var/log/vuls $VULS_ROOT
#  RUN go get github.com/kotakanbe/go-cve-dictionary
#  RUN go get github.com/future-architect/vuls

RUN go get -v -d github.com/kotakanbe/go-cve-dictionary \
    && cd $GOPATH/src/github.com/kotakanbe/go-cve-dictionary \
    && glide install \
    && go install

RUN go get -v -d github.com/future-architect/vuls \
    && cd $GOPATH/src/github.com/future-architect/vuls \
    && glide install \
    && go install

# Copy custom Scripts
COPY ./scripts/ ${VULS_ROOT}/scripts
RUN chmod 755 ${VULS_ROOT}/scripts/*


#Vulrepo Install
RUN git clone https://github.com/usiusi360/vulsrepo /tmp/vulsrepo
RUN mkdir /usr/share/nginx/html/vulsrepo/
RUN cp -rp /tmp/vulsrepo/src/* /usr/share/nginx/html/vulsrepo
RUN rm -rf /tmp/vulsrepo

#Home
WORKDIR /opt/vuls
EXPOSE 80 443
CMD ["nginx", "-g", "daemon off;"]

