#!/bin/bash
VULS_ROOT=/opt/vuls
#VULS_CONF=${VULS_ROOT}/conf
cd $VULS_ROOT
go-cve-dictionary fetchnvd -last2y

