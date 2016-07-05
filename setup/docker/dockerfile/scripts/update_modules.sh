#!/bin/bash

cd $GOPATH/src/github.com/future-architect/vuls
git pull origin master
glide install
go install


cd $GOPATH/src/github.com/kotakanbe/go-cve-dictionary
git pull origin master
glide install
go install

git clone https://github.com/usiusi360/vulsrepo /tmp/vulsrepo
cp -rp /tmp/vulsrepo/src/* /usr/share/nginx/html/vulsrepo
rm -rf /tmp/vulsrepo

