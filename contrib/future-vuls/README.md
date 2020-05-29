# future-vuls

## Main Features

- upload vuls results json to future-vuls

## Installation

```
git clone https://github.com/future-architect/vuls.git
make build-future-vuls
```

## Command Reference

```
Usage:
  future-vuls [command]

Available Commands:
  help        Help about any command
  upload      Upload to FutureVuls

Flags:
  -h, --help   help for future-vuls

Use "future-vuls [command] --help" for more information about a command.
```

## Usage

- update results json

```
 cat results.json | future-vuls upload --stdin --token xxxx --url https://xxxx --group-id 1
```