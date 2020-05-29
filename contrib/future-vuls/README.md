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
Upload to FutureVuls

Usage:
  future-vuls upload [flags]

Flags:
      --config string   config file (default is $HOME/.cobra.yaml)
  -g, --group-id int    future vuls group id, ENV: VULS_GROUP_ID
  -h, --help            help for upload
  -s, --stdin           input from stdin. ENV: VULS_STDIN
  -t, --token string    future vuls token
      --url string      future vuls upload url
      --uuid string     server uuid. ENV: VULS_SERVER_UUID
```

## Usage

- update results json

```
 cat results.json | future-vuls upload --stdin --token xxxx --url https://xxxx --group-id 1 --uuid xxxx
```