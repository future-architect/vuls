
# Vuls: VULnerability Scanner

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](http://goo.gl/forms/xm5KFo35tu)
[![License](https://img.shields.io/github/license/future-architect/vuls.svg?style=flat-square)](https://github.com/future-architect/vuls/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/future-architect/vuls.svg?branch=master)](https://travis-ci.org/future-architect/vuls)
[![Go Report Card](https://goreportcard.com/badge/github.com/future-architect/vuls)](https://goreportcard.com/report/github.com/future-architect/vuls)
[![Contributors](https://img.shields.io/github/contributors/future-architect/vuls.svg)](https://github.com/future-architect/vuls/graphs/contributors)

![Vuls-logo](img/vuls_logo.png)

Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.
We have a slack team. [Join slack team](http://goo.gl/forms/xm5KFo35tu)
Twitter: [@vuls_en](https://twitter.com/vuls_en)

![Vuls-Abstract](img/vuls-abstract.png)

![Vulsrepo](https://raw.githubusercontent.com/usiusi360/vulsrepo/master/gallery/demo.gif)

[![asciicast](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck.png)](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck)

![Vuls-slack](img/vuls-slack-en.png)

----

## NEWS

| Version     | Main Feature |  Date |
|:------------|:---------------------------------|:--------------------|
| [v0.7.0](https://github.com/future-architect/vuls/releases/tag/v0.7.0) | WordPress Vulnerability Scan | 2019/Apr/8 |
| [v0.6.3](https://github.com/future-architect/vuls/releases/tag/v0.6.3) | GitHub Integration | 2019/Feb/20 |
| [v0.6.2](https://github.com/future-architect/vuls/releases/tag/v0.6.2) | Add US-CERT/JPCERT Alerts as VulnSrc | 2019/Jan/23 |
| [v0.6.1](https://github.com/future-architect/vuls/releases/tag/v0.6.1) | BugFix | 2018/Nov/16 |
| [v0.6.0](https://github.com/future-architect/vuls/releases/tag/v0.6.0) | Add ExploitDB as VulnSrc | 2018/Nov/3 |
| [v0.5.0](https://github.com/future-architect/vuls/releases/tag/v0.5.0) | Scan accuracy improvement | 2018/Aug/27 |

----

## Abstract

For a system administrator, having to perform security vulnerability analysis and software update on a daily basis can be a burden.
To avoid downtime in a production environment, it is common for a system administrator to choose not to use the automatic update option provided by the package manager and to perform update manually.
This leads to the following problems.

- The system administrator will have to constantly watch out for any new vulnerabilities in NVD (National Vulnerability Database) or similar databases.
- It might be impossible for the system administrator to monitor all the software if there are a large number of software packages installed in the server.
- It is expensive to perform analysis to determine the servers affected by new vulnerabilities. The possibility of overlooking a server or two during analysis is there.

Vuls is a tool created to solve the problems listed above. It has the following characteristics.

- Informs users of the vulnerabilities that are related to the system.
- Informs users of the servers that are affected.
- Vulnerability detection is done automatically to prevent any oversight.
- A report is generated on a regular basis using CRON or other methods. to manage vulnerability.

![Vuls-Motivation](img/vuls-motivation.png)

----

## Main Features

### Scan for any vulnerabilities in Linux/FreeBSD Server

[Supports major Linux/FreeBSD](https://vuls.io/docs/en/supported-os.html)

- Alpine, Amazon Linux, CentOS, Debian, Oracle Linux, Raspbian, RHEL, SUSE Enterprise Linux, and Ubuntu
- FreeBSD
- Cloud, on-premise, and Docker

### High-quality scan

Vuls uses multiple vulnerability databases

- [NVD](https://nvd.nist.gov/)
- [JVN(Japanese)](http://jvndb.jvn.jp/apis/myjvn/)
- OVAL
  - [Debian](https://www.debian.org/security/oval/)
  - [Oracle Linux](https://linux.oracle.com/security/oval/)
  - [RedHat](https://www.redhat.com/security/data/oval/)
  - [SUSE](http://ftp.suse.com/pub/projects/security/oval/)
  - [Ubuntu](https://people.canonical.com/~ubuntu-security/oval/)

- [Alpine-secdb](https://git.alpinelinux.org/cgit/alpine-secdb/)
- [Debian Security Bug Tracker](https://security-tracker.debian.org/tracker/)
- [Red Hat Security Advisories](https://access.redhat.com/security/security-updates/)
- Commands (yum, zypper, and pkg-audit)
  - RHSA/ALAS/ELSA/FreeBSD-SA
- [Exploit Database](https://www.exploit-db.com/)
- [US-CERT](https://www.us-cert.gov/ncas/alerts)
- [JPCERT](http://www.jpcert.or.jp/at/2019.html)
- [WPVulnDB](https://wpvulndb.com/api)
- Changelog

### Fast scan and Deep scan

[Fast Scan](https://vuls.io/docs/en/architecture-fast-scan.html)

- Scan without root privilege, no dependencies
- Almost no load on the scan target server
- Offline mode scan with no internet access. (CentOS, Debian, Oracle Linux, Red Hat, and Ubuntu)

[Fast Root Scan](https://vuls.io/docs/en/architecture-fast-root-scan.html)

- Scan with root privilege
- Almost no load on the scan target server
- Detect processes affected by update using yum-ps (Amazon Linux, CentOS, Oracle Linux, and RedHat)
- Detect processes which updated before but not restarting yet using checkrestart of debian-goodies (Debian and Ubuntu)
- Offline mode scan with no internet access. (CentOS, Debian, Oracle Linux, Red Hat, and Ubuntu)

[Deep Scan](https://vuls.io/docs/en/architecture-deep-scan.html)

- Scan with root privilege
- Parses the Changelog
    Changelog has a history of version changes. When a security issue is fixed, the relevant CVE ID is listed.
    By parsing the changelog and analysing the updates between the installed version of software on the server and the newest version of that software
    it's possible to create a list of all vulnerabilities that need to be fixed.
- Sometimes load on the scan target server

### [Remote scan, Local scan mode, Server mode](https://vuls.io/docs/en/architecture-remote-local.html)

[Remote scan mode](https://vuls.io/docs/en/architecture-remote-scan.html)

- User is required to only set up one machine that is connected to other target servers via SSH

[Local scan mode](https://vuls.io/docs/en/architecture-local-scan.html)

- If you don't want the central Vuls server to connect to each server by SSH, you can use Vuls in the Local Scan mode.

[Server mode](https://vuls.io/docs/en/usage-server.html)

- First, start Vuls in server mode and listen as an HTTP server.
- Start Vuls in server mode and listen as an HTTP server.
- Next, issue a command on the scan target server to collect software information. Then send the result to Vuls Server via HTTP. You receive the scan results as JSON format.
- No SSH needed, No Scanner needed. Only issuing Linux commands directory on the scan tareget server.

### **Dynamic** Analysis

- It is possible to acquire the state of the server by connecting via SSH and executing the command.
- Vuls warns when the scan target server was updated the kernel etc. but not restarting it.

### Scan vulnerabilities of non-OS packages

- [Common Platform Enumeration (CPE) based Scan](https://vuls.io/docs/en/usage-scan-non-os-packages.html#how-to-search-cpe-name-by-software-name)
  - Scan middleware, programming language libraries and framework for vulnerability
  - Support software registered in CPE

## Integration

- [GitHub Security Alerts](https://vuls.io/docs/en/usage-scan-non-os-packages.html#usage-integrate-with-github-security-alerts)
- [OWASP Dependency Check](https://vuls.io/docs/en/usage-scan-non-os-packages.html#usage-integrate-with-owasp-dependency-check-to-automatic-update-when-the-libraries-are-updated-experimental)
- [WordPress](https://vuls.io/docs/en/usage-scan-wordpress.html)

## MISC

- Nondestructive testing
- Pre-authorization is *NOT* necessary before scanning on AWS
  - Vuls works well with Continuous Integration since tests can be run every day. This allows you to find vulnerabilities very quickly.
- Auto-generation of configuration file template
  - Auto-detection of servers set using CIDR, generate configuration file template
- Email and Slack notification is possible (supports Japanese language)
- Scan result is viewable on accessory software, TUI Viewer in a terminal or Web UI ([VulsRepo](https://github.com/usiusi360/vulsrepo)).

----

## What Vuls Doesn't Do

- Vuls doesn't update the vulnerable packages.

----

## Document

For more information such as Installation, Tutorial, Usage, visit [vuls.io](https://vuls.io/)
[日本語翻訳ドキュメント](https://vuls.io/ja/)

----

## Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created vuls and [these fine people](https://github.com/future-architect/vuls/graphs/contributors) have contributed.

----

## Change Log

Please see [CHANGELOG](https://github.com/future-architect/vuls/blob/master/CHANGELOG.md).

----

## Stargazers over time

[![Stargazers over time](https://starcharts.herokuapp.com/future-architect/vuls.svg)](https://starcharts.herokuapp.com/future-architect/vuls)

-----;

## License

Please see [LICENSE](https://github.com/future-architect/vuls/blob/master/LICENSE).
