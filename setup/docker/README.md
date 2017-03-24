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

# Caution

This image is built per commit.
If you want to use the latest docker image, you should remove the existing image, and pull it once again.

1. Confirm your vuls version

- go-cve-dictionary

```console
$ docker run  --rm  vuls/go-cve-dictionary -v

go-cve-dictionary v0.0.xxx xxxx
```

- vuls

```console
$ docker run  --rm  vuls/vuls -v

vuls v0.0.xxx xxxx
```

2. Remove your old docker images

- go-cve-dictionary

```
$ docker rmi vuls/go-cve-dictionary
```

- vuls

```
$ docker rmi vuls/vuls
```

3. Pull new vuls docker images

- go-cve-dictionary

```
$ docker pull vuls/go-cve-dictionary
```

- vuls

```
$ docker pull vuls/vuls
```

4. Confirm your vuls version

```console
$ docker run  --rm  vuls/go-cve-dictionary -v

go-cve-dictionary v0.1.xxx xxxx
```

- vuls

```console
$ docker run  --rm  vuls/vuls -v

vuls v0.1.xxx xxxx
```


# How to use this image

1. fetch nvd (vuls/go-cve-dictionary)
1. configuration (vuls/vuls)
1. configtest (vuls/vuls)
1. scan (vuls/vuls)
1. vulsrepo (vuls/vulsrepo)

## Step1. Fetch NVD

```console
$ for i in `seq 2002 $(date +"%Y")`; do \
    docker run --rm -it \
    -v $PWD:/vuls \
    -v $PWD/go-cve-dictionary-log:/var/log/vuls \
    vuls/go-cve-dictionary fetchnvd -years $i; \
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


## Step3. Configtest

```console
$ docker run --rm -it\
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    vuls/vuls configtest \
    -config=./config.toml # path to config.toml in docker
```

## Step4. Scan

```console
$ docker run --rm -it \
    -v ~/.ssh:/root/.ssh:ro \
    -v $PWD:/vuls \
    -v $PWD/vuls-log:/var/log/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    -e "TZ=Asia/Tokyo" \
    vuls/vuls scan \
    -config=./config.toml # path to config.toml in docker
```

## Step5. Report

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

## Step6. vulsrepo

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
