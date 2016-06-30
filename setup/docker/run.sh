#!/bin/bash
tries=0

function isopen {
    tries=$1
    nmap -Pn -T4 -p 1323 127.0.0.1|grep -iq open
    if [ $? -ne 0 ]; then
        if [ $tries -lt 5 ]; then
            let tries++
            startserver $tries
        else
            return 1
        fi
    else
        return 0
    fi
}
function startserver {
    tries=$1
    go-cve-dictionary server &
    sleep 2
    isopen $tries
}

startserver $tries
if [ $? -ne 1 ]; then
    vuls scan -config /app/config.toml -report-slack
fi
