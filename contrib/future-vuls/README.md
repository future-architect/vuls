# future-vuls

## Main Features

- `future-vuls upload` 
  - upload vuls results json to future-vuls

- `future-vuls discover`
  - Explore hosts within the CIDR range using ping command.
  - Describe the information on the found hosts in a toml-formatted file.

Structure of toml-formatted file
```
[server.{IpAddr}]
ip = {IpAddr}
uuid = {UUID}
cpe_uri = []
fvuls_sync = false
```

- `future-vuls add-server`
  - Register hosts with FvulsSync set to true as pseudo servers in Fvuls.
  - Add the acquired UUID to the toml-formatted file
 
- `future-vuls add-cpe`
  -  Upload CPE information obtained by executing snmp2cpe(https://github.com/future-architect/vuls/pull/1625) on the specified(FvulsSync is true and UUID is obtained) hosts to Fvuls
<br>

1.　`future-vuls discover`

2.　`future-vuls add-server`

3.　`future-vuls add-cpe`

These three commands are used to manage the CPE of network devices, and by executing the commands in the order from the top, you can manage the CPE of each device in Fvuls
## Installation

```
git clone https://github.com/future-architect/vuls.git
cd vuls
make build-future-vuls
```

## Command Reference

```
Usage:
  future-vuls [command]

Available Commands:
  add-cpe     scan device CPE and upload to Fvuls server. Default outputFile is ./discover_list.toml
  add-server  upload device information to Fvuls as a pseudo server. Default outputFile is ./discover_list.toml
  completion  Generate the autocompletion script for the specified shell
  discover    discover hosts with CIDR range. Default outputFile is ./discover_list.toml
  help        Help about any command
  upload      Upload to FutureVuls
  version     Show version

Flags:
  -h, --help   help for future-vuls

Use "future-vuls [command] --help" for more information about a command.
```

### Subcommands

```
./future-vuls upload -h
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

```
./future-vuls discover -h
discover hosts with CIDR range. The default outputFile is ./discover_list.toml

Usage:
  future-vuls discover --cidr <CIDR Range> --output <Output_File> [flags]

Examples:
future-vuls discover --cidr 192.168.0.0/24 --output discover_list.toml

Flags:
      --cidr string     cidr range
  -h, --help            help for discover
      --output string   output file
```

```
./future-vuls add-server -h
Register hosts for Fvuls as a pseudo server. The default outputFile is ./discover_list.toml

Usage:
  future-vuls add-server --token <VULS_TOKEN> --output <Output_File> [flags]

Examples:
future-vuls add-server --token <VULS_TOKEN> --output ./discover_list.toml

Flags:
  -h, --help            help for add-server
      --output string   output file
  -t, --token string    future vuls token ENV: VULS_TOKEN
      --url string      future vuls upload url ENV: VULS_URL
```

```
./future-vuls add-cpe -h
scan device CPE and upload to Fvuls. The default outputFile is ./discover_list.toml

Usage:
  future-vuls add-cpe --token <VULS_TOKEN> --output <Output_File> [flags]

Examples:
future-vuls add-cpe --token <VULS_TOKEN>

Flags:
  -h, --help                 help for add-cpe
      --output string        output file
      --snmpVersion string   snmp version v1,v2c and v3. default: v2c
  -t, --token string         future vuls token ENV: VULS_TOKEN
      --url string           future vuls upload url ENV: VULS_URL
```

## Usage

- `future-vuls upload`

```
 cat results.json | future-vuls upload --stdin --token xxxx --url https://xxxx --group-id 1 --uuid xxxx
```
- `future-vuls discover`
```
$ ./future-vuls discover --cidr 192.168.0.0/24
Discovering 192.168.0.0/24...
New host found 192.168.0.1
New host found 192.168.0.2
New host found 192.168.0.3
New host found 192.168.0.4
New host found 192.168.0.5
New host found 192.168.0.7
New host found 192.168.0.8
Successfully wrote to ./discover_list.toml
```
- `future-vuls add-server`
```
$ ./future-vuls add-server --url "https://rest.vuls.biz/v1" --token fvgr-528ec289-2516-11ee-b1e6-0a58a9feac02
192.168.0.2: Adding to Fvuls server...
192.168.0.2: Done.
Successfully wrote to ./discover_list.toml
```
- `future-vuls add-cpe`
```
$ ./future-vuls add-cpe --token fvgr-528ec289-2516-11ee-b1e6-0a58a9feac02 --url "https://rest.vuls.biz/v1"
Uploading CPE to https://rest.2119e7c929.vuls.biz/v1/pkgCpe/cpe...
192.168.0.2: Done.
192.168.0.2: Found new cpe: cpe:2.3:h:fortinet:fortigate-50e:-:*:*:*:*:*:*:*
192.168.0.2: Found new cpe: cpe:2.3:o:fortinet:fortios:5.4.6:*:*:*:*:*:*:*
192.168.0.2: Upload CPE...
192.168.0.2: Done.
192.168.0.2: Successfully uploaded 2 cpes to Fvuls.
```
