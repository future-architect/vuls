# VulsRepo-Docker

This is the Git repo of the official Docker image for vulsrepo.
See the [Hub page](https://hub.docker.com/r/vuls/vulsrepo/) for the full readme on how to use the Docker image and for information regarding contributing and issues.

# Supported tags and respective `Dockerfile` links

- [`latest` (*vulsrepo:latest Dockerfile*)](https://github.com/future-architect/vuls/blob/master/setup/docker/vulsrepo/latest/Dockerfile)

# Caution

This image is built per commit.
If you want to use the latest docker image, you should remove the existing image, and pull it once again.

# What is vulsrepo?

VulsRepo is visualized based on the json report output in [vuls](https://github.com/future-architect/vuls).

# How to use this image

## vulsrepo

```console
$docker run -dt \
    -v $PWD:/vuls \
    -p 5111:5111 \
    vuls/vulsrepo
```

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
