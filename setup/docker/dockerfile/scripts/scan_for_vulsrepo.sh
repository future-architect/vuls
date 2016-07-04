#!/bin/bash
VULS_ROOT=/opt/vuls
VULS_CONF=${VULS_ROOT}/conf
NGINX_VULSREPO_ROOT=/usr/share/nginx/html/vulsrepo
cd $VULS_ROOT
vuls scan -report-json --cve-dictionary-dbpath=${VULS_ROOT}/cve.sqlite3 -config=${VULS_CONF}/config.toml 
ln -sf ${VULS_ROOT}/results/current ${NGINX_VULSREPO_ROOT}/current
