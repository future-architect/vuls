# goval-dictionary-Docker

This is the Git repo of the official Docker image for goval-dictionary.
See the [Hub page](https://hub.docker.com/r/vuls/goval-dictionary/) for the full readme on how to use the Docker image and for information regarding contributing and issues.

# Supported tags and respective `Dockerfile` links

- [`latest` (*goval-dictionary:latest Dockerfile*)](https://github.com/future-architect/vuls/blob/master/setup/docker/goval-dictionary/latest/Dockerfile)

# Caution

This image is built per commit.
If you want to use the latest docker image, you should remove the existing image, and pull it once again.

- Remove old docker image

```
$ docker rmi vuls/goval-dictionary
```

- Pull new docker image

```
$ docker pull vuls/goval-dictionary
```

# What is goval-dictionary?

This is tool to build a local copy of the OVAL. The local copy is generated in sqlite format, and the tool has a server mode for easy querying.

# How to use this image

## check vuls version

```
$ docker run --rm vuls/goval-dictionary -v
```

## fetch-redhat

```console
$ for i in `seq 5 7`; do \
    docker run --rm -it \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-redhat $i; \
  done
```

## fetch-debian

```console
$ for i in `seq 7 10`; do \
    docker run --rm -it \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-debian $i; \
  done
```

## fetch-ubuntu

```console
$ for i in `seq 12 2 16`; do \
    docker run --rm -it \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-ubuntu $i; \
  done
```

## fetch-suse

```console
$  docker run --rm -it \
  -v $PWD:/vuls \
  -v $PWD/goval-dictionary-log:/var/log/vuls \
  vuls/goval-dictionary fetch-suse -opensuse 13.2
```

## fetch-oracle

```console
$  docker run --rm -it \
  -v $PWD:/vuls \
  -v $PWD/goval-dictionary-log:/var/log/vuls \
  vuls/goval-dictionary fetch-oracle
```

## server

```console
$ docker run -dt \
    --name goval-dictionary \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    --expose 1324 \
    -p 1324:1324 \
    vuls/goval-dictionary server --bind=0.0.0.0
```

Prease refer to [this](https://hub.docker.com/r/vuls/goval-dictionary).

## vuls

Please refer to [this](https://hub.docker.com/r/vuls/vuls/).

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
