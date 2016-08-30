#!/bin/bash
VULS_ROOT=/opt/vuls
VULS_CONF=${VULS_ROOT}/conf
APACHE_VULSREPO_ROOT=/var/www/html/vulsrepo
cd $VULS_ROOT
vuls scan -report-json --cve-dictionary-dbpath=${VULS_ROOT}/cve.sqlite3 -config=${VULS_CONF}/config.toml
rm ${APACHE_VULSREPO_ROOT}/results/*
cp ${VULS_ROOT}/results/current/* ${APACHE_VULSREPO_ROOT}/results
