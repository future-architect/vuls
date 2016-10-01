# Vuls Docker components

This is the Git repo of the official Docker image for vuls.

# Supported tags and respective `Dockerfile` links

- go-cve-dictionary
  - [`latest` (*go-cve-dictionary:latest Dockerfile*)]()
- vuls
  - [`latest` (*vuls:latest Dockerfile*)]()
- vulsrepo
  - [`latest` (*vulsrepo:latest Dockerfile*)]()

This image version is same as the github repository version.

# How to use this image

1. fetch nvd (vuls/go-cve-dictionary)
1. configuration (vuls/vuls)
1. prepare (vuls/vuls)
1. scan (vuls/vuls)
1. vulsrepo (vuls/vulsrepo)

## Step1. Fetch NVD

```console
$ for i in {2002..2016}; do \
    docker run --rm -it \
    -v $PWD:/vuls  vuls/go-cve-dictionary fetchnvd -years $i; \
  done
```

## Step2. Configuration

Create config.toml referring to [this](https://github.com/future-architect/vuls#configuration).

```toml
[servers]

[servers.amazon]
host         = "54.249.93.16"
port        = "22"
user        = "vuls-user"
keyPath     = "/root/.ssh/id_rsa" # path to ssh private key in docker
```
　

```console
$ docker run --rm \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    vuls/vuls configtest \
    -config=./config.toml # path to config.toml in docker
```

## Step3. Prepare

```console
$ docker run --rm \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    vuls/vuls prepare \
    -config=./config.toml # path to config.toml in docker
```

## Step4. Scan

```console
$ docker run --rm -it \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    -e "TZ=Asia/Tokyo" \
    vuls/vuls scan \
    -cve-dictionary-dbpath=/vuls/cve.sqlite3 \
    -report-json \
    -config=./config.toml # path to config.toml in docker
```

## Step5. vulsrepo

```console
$docker run -dt \
    -v $PWD:/vuls \
    -p 80:80 \
    vuls/vulsrepo
```

# User Feedback

## Documentation

Documentation for this image is stored in the [`docker/` directory]() of the [`future-architect/vuls` GitHub repo](https://github.com/future-architect/vuls). 

## Issues

If you have any problems with or questions about this image, please contact us through a [GitHub issue](https://github.com/future-architect/vuls/issues). 

## Contributing

1. fork a repository: github.com/future-architect/vuls to github.com/you/repo
1. get original code: go get github.com/future-architect/vuls
1. work on original code
1. add remote to your repo: git remote add myfork https://github.com/you/repo.git
1. push your changes: git push myfork
1. create a new Pull Request
