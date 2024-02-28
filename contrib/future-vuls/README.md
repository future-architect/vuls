# future-vuls

## Main Features

- `future-vuls upload` 
  - upload vuls results json to future-vuls

- `future-vuls discover`
 -  Explores hosts within the CIDR range using the ping command
 -  Describes the information including CPEs on the found hosts in a toml-formatted file
 -  Executes snmp2cpe(https://github.com/future-architect/vuls/pull/1625) to active hosts to obtain CPE,
    Commands running internally `snmp2cpe v2c {IPAddr} public  | snmp2cpe convert`

Structure of toml-formatted file
```
[server.{ip}]
ip = {IpAddr}
server_name = ""
uuid = {UUID}
cpe_uris = []
fvuls_sync = false
```
 
- `future-vuls add-cpe`
  -  Create pseudo server to Fvuls to obtain uuid and Upload CPE information on the specified(FvulsSync is true and UUID is obtained) hosts to Fvuls
  -  Fvuls_Sync must be rewritten to true to designate it as the target of the command


1. `future-vuls discover`

2. `future-vuls add-cpe`

These two commands are used to manage the CPE of network devices, and by executing the commands in the order from the top, you can manage the CPE of each device in Fvuls

toml file after command execution
```
["192.168.0.10"]
  ip = "192.168.0.10"
  server_name = "192.168.0.10"
  uuid = "e811e2b1-9463-d682-7c79-a4ab37de28cf"
  cpe_uris = ["cpe:2.3:h:fortinet:fortigate-50e:-:*:*:*:*:*:*:*", "cpe:2.3:o:fortinet:fortios:5.4.6:*:*:*:*:*:*:*"]
  fvuls_sync = true
```
## Installation

```
git clone https://github.com/future-architect/vuls.git
cd vuls
make build-future-vuls
```

## Command Reference

```
./future-vuls -h
Usage:
  future-vuls [command]

Available Commands:
  add-cpe     Create a pseudo server in Fvuls and register CPE. Default outputFile is ./discover_list.toml
  completion  Generate the autocompletion script for the specified shell
  discover    discover hosts with CIDR range. Run snmp2cpe on active host to get CPE. Default outputFile is ./discover_list.toml
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
discover hosts with CIDR range. Run snmp2cpe on active host to get CPE. Default outputFile is ./discover_list.toml

Usage:
  future-vuls discover --cidr <CIDR_RANGE> --output <OUTPUT_FILE> [flags]

Examples:
future-vuls discover --cidr 192.168.0.0/24 --output discover_list.toml

Flags:
      --cidr string           cidr range
      --community string      snmp community name. default: public
  -h, --help                  help for discover
      --output string         output file
      --snmp-version string   snmp version v1,v2c and v3. default: v2c
```

```
./future-vuls add-cpe -h
Create a pseudo server in Fvuls and register CPE. Default outputFile is ./discover_list.toml

Usage:
  future-vuls add-cpe --token <VULS_TOKEN> --output <OUTPUT_FILE> [flags]

Examples:
future-vuls add-cpe --token <VULS_TOKEN>

Flags:
  -h, --help                help for add-cpe
      --http-proxy string   proxy url
      --output string       output file
  -t, --token string        future vuls token ENV: VULS_TOKEN
```

## Usage

- `future-vuls upload`

```
 cat results.json | future-vuls upload --stdin --token xxxx --url https://xxxx --group-id 1 --uuid xxxx
```
- `future-vuls discover`
```
./future-vuls discover --cidr 192.168.0.1/24
Discovering 192.168.0.1/24...
192.168.0.1: Execute snmp2cpe...
failed to execute snmp2cpe. err: failed to execute snmp2cpe. err: exit status 1
192.168.0.2: Execute snmp2cpe...
failed to execute snmp2cpe. err: failed to execute snmp2cpe. err: exit status 1
192.168.0.4: Execute snmp2cpe...
failed to execute snmp2cpe. err: failed to execute snmp2cpe. err: exit status 1
192.168.0.5: Execute snmp2cpe...
failed to execute snmp2cpe. err: failed to execute snmp2cpe. err: exit status 1
192.168.0.6: Execute snmp2cpe...
New network device found 192.168.0.6
wrote to discover_list.toml
```
- `future-vuls add-cpe`
```
./future-vuls add-cpe --token fvgr-686b92af-5216-11ee-a241-0a58a9feac02
Creating 1 pseudo server...
192.168.0.6: Created FutureVuls pseudo server ce024b45-1c59-5b86-1a67-e78a40dfec01
wrote to discover_list.toml

Uploading 1 server's CPE...
192.168.0.6: Uploaded CPE cpe:2.3:h:fortinet:fortigate-50e:-:*:*:*:*:*:*:*
192.168.0.6: Uploaded CPE cpe:2.3:o:fortinet:fortios:5.4.6:*:*:*:*:*:*:*
```
