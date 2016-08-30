#!/bin/bash

cd $GOPATH/src/github.com/future-architect/vuls
git pull origin master
glide install
go install


cd $GOPATH/src/github.com/kotakanbe/go-cve-dictionary
git pull origin master
glide install
go install


cd /var/www/html/vulsrepo
git pull origin master
