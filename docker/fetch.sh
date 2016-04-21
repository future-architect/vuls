#!/bin/bash
 for i in {2002..2016}; do go-cve-dictionary fetchnvd -years $i ; done
