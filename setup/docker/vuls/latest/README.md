# Vuls-Docker

This is the Git repo of the official Docker image for vuls.
See the [Hub page](https://hub.docker.com/r/vuls/vuls/) for the full readme on how to use the Docker image and for information regarding contributing and issues.

# Supported tags and respective `Dockerfile` links

- [`latest` (*vuls:latest Dockerfile*)](https://github.com/future-architect/vuls/blob/master/setup/docker/vuls/latest/Dockerfile)

# Caution

This image is built per commit.
If you want to use the latest docker image, you should remove the existing image, and pull it once again.

- Remove old docker image

```
$ docker rmi vuls/vuls
```

- Pull new docker image

```
$ docker pull vuls/vuls
```

# What is Vuls?

Vuls is the Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.
Please see the [Documentation](https://github.com/future-architect/vuls)

![logo](https://github.com/future-architect/vuls/blob/master/img/vuls_logo.png?raw=true)

# How to use this image

## check vuls version

```
$ docker run  --rm  vuls/vuls -v
```

## config

Create config.toml referring to [this](https://github.com/future-architect/vuls#configuration).

```toml
[servers]

[servers.amazon]
host         = "54.249.93.16"
port        = "22"
user        = "vuls-user"
keyPath     = "/root/.ssh/id_rsa"  # path to ssh private key in docker
```


## configtest

```console
$ docker run --rm -it \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    vuls/vuls configtest \
    -config=./config.toml # path to config.toml in docker
```

## scan

```console
$ docker run --rm -it \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    vuls/vuls scan \
    -config=./config.toml # path to config.toml in docker
```

## Report

```console
$ docker run --rm -it \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    vuls/vuls report \
    -cvedb-path=/vuls/cve.sqlite3 \
    -format-short-text \
    -config=./config.toml # path to config.toml in docker
```

## tui

```console
$ docker run --rm -it \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    vuls/vuls tui \
    -cvedb-path=/vuls/cve.sqlite3 
```

## vulsrepo

Prease refer to [this](https://hub.docker.com/r/vuls/vulsrepo/).

# User Feedback

## Documentation

Documentation for this image is stored in the [`docker/` directory](https://github.com/future-architect/vuls/tree/master/setup/docker) of the [`future-architect/vuls` GitHub repo](https://github.com/future-architect/vuls). 

## Issues

If you have any problems with or questions about this image, please contact us through a [GitHub issue](https://github.com/future-architect/vuls/issues). 

## Contributing

1. fork a repository: github.com/future-architect/vuls to github.com/you/repo
1. get original code: go get github.com/future-architect/vuls
1. work on original code
1. add remote to your repo: git remote add myfork https://github.com/you/repo.git
1. push your changes: git push myfork
1. create a new Pull Request
