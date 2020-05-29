# trivy-to-vuls

## Main Features

- convert trivy's results json to vuls's report json

## Installation

```
git clone https://github.com/future-architect/vuls.git
make build-trivy-to-vuls
```

## Command Reference

```
Parse trivy json to vuls results

Usage:
  trivy-to-vuls parse [flags]

Flags:
  -h, --help                          help for parse
  -s, --stdin                         input from stdin
  -d, --trivy-json-dir string         trivy json dir (default "./")
  -f, --trivy-json-file-name string   trivy json file name (default "results.json")
```

## Usage

- use trivy output

```
 trivy -q image -f=json python:3.4-alpine | trivy-to-vuls parse --stdin
```
