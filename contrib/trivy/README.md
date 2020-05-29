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
Usage:
  trivy-to-vuls [command]

Available Commands:
  help        Help about any command
  parse       Parse trivy json to vuls results

Flags:
  -h, --help   help for trivy-to-vuls

Use "trivy-to-vuls [command] --help" for more information about a command.
```

## Usage

- use trivy output

```
 trivy -q image -f=json python:3.4-alpine | trivy-to-vuls parse --stdin
```
