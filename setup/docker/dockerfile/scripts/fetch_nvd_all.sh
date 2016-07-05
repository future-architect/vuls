#!/bin/bash
VULS_ROOT=/opt/vuls
#VULS_CONF=${VULS_ROOT}/conf
cd $VULS_ROOT
for i in {2002..2016}; do go-cve-dictionary fetchnvd -years $i; done

