# snmp2cpe

## Main Features

- Estimate hardware and OS CPE from SNMP reply of network devices

## Installation

```console
$ git clone https://github.com/future-architect/vuls.git
$ make build-snmp2cpe
```

## Command Reference

```console
$ snmp2cpe help
snmp2cpe: SNMP reply To CPE

Usage:
  snmp2cpe [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  convert     snmpget reply to CPE
  help        Help about any command
  v1          snmpget with SNMPv1
  v2c         snmpget with SNMPv2c
  v3          snmpget with SNMPv3
  version     Print the version

Flags:
  -h, --help   help for snmp2cpe

Use "snmp2cpe [command] --help" for more information about a command.
```

## Usage

```console
$ snmp2cpe v2c --debug 192.168.1.99 public
2023/03/28 14:16:54 DEBUG: .1.3.6.1.2.1.1.1.0 -> 
2023/03/28 14:16:54 DEBUG: .1.3.6.1.2.1.47.1.1.1.1.12.1 -> Fortinet
2023/03/28 14:16:54 DEBUG: .1.3.6.1.2.1.47.1.1.1.1.7.1 -> FGT_50E
2023/03/28 14:16:54 DEBUG: .1.3.6.1.2.1.47.1.1.1.1.10.1 -> FortiGate-50E v5.4.6,build1165b1165,171018 (GA)
{"192.168.1.99":{"entPhysicalTables":{"1":{"entPhysicalMfgName":"Fortinet","entPhysicalName":"FGT_50E","entPhysicalSoftwareRev":"FortiGate-50E v5.4.6,build1165b1165,171018 (GA)"}}}}

$ snmp2cpe v2c 192.168.1.99 public | snmp2cpe convert
{"192.168.1.99":["cpe:2.3:h:fortinet:fortigate-50e:-:*:*:*:*:*:*:*","cpe:2.3:o:fortinet:fortios:5.4.6:*:*:*:*:*:*:*"]}
```
