FROM golang:1.6
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y git openssh-client gcc
WORKDIR /app
RUN go get github.com/kotakanbe/go-cve-dictionary
RUN go get github.com/future-architect/vuls
COPY fetch.sh .
RUN /bin/bash /app/fetch.sh
COPY config.toml .
COPY run.sh .
ENTRYPOINT ["/bin/bash", "/app/run.sh"]
COPY id_rsa .
COPY id_rsa.pub .
