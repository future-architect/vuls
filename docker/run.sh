#!/bin/bash
go-cve-dictionary server &
sleep 2
vuls scan -config /app/config.toml -report-slack
