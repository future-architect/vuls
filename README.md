
# Vuls: VULnerability Scanner

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](http://goo.gl/forms/xm5KFo35tu)
[![License](https://img.shields.io/github/license/future-architect/vuls.svg?style=flat-square)](https://github.com/future-architect/vuls/blob/master/LICENSE.txt)


Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.

We have a slack team. [Join slack team](http://goo.gl/forms/xm5KFo35tu)  

[README in Japanese](https://github.com/future-architect/vuls/blob/master/README.ja.md)  
[README in French](https://github.com/future-architect/vuls/blob/master/README.fr.md)  

[![asciicast](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck.png)](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck)

![Vuls-slack](img/vuls-slack-en.png)



----

# Abstract

For a system administrator, having to perform security vulnerability analysis and software update on a daily basis can be a burden.
To avoid downtime in production environment, it is common for system administrator to choose not to use the automatic update option provided by package manager and to perform update manually.
This leads to the following problems.
- System administrator will have to constantly watch out for any new vulnerabilities in NVD(National Vulnerability Database) or similar databases.
- It might be impossible for the system administrator to monitor all the software if there are a large number of software installed in server.
- It is expensive to perform analysis to determine the servers affected by new vulnerabilities. The possibility of overlooking a server or two during analysis is there.


Vuls is a tool created to solve the problems listed above. It has the following characteristics.
- Informs users of the vulnerabilities that are related to the system.
- Informs users of the servers that are affected.
- Vulnerability detection is done automatically to prevent any oversight.
- Report is generated on regular basis using CRON or other methods. to manage vulnerability.

![Vuls-Motivation](img/vuls-motivation.png)

----

# Main Features

- Scan for any vulnerabilities in Linux/FreeBSD Server
    - Supports Ubuntu, Debian, CentOS, Amazon Linux, RHEL, FreeBSD
    - Cloud, on-premise, Docker
- Scan middleware that are not included in OS package management
    - Scan middleware, programming language libraries and framework for vulnerability
    - Support software registered in CPE
- Agentless architecture
    - User is required to only setup one machine that is connected to other target servers via SSH
- Auto generation of configuration file template
    - Auto detection of servers set using CIDR, generate configuration file template
- Email and Slack notification is possible (supports Japanese language) 
- Scan result is viewable on accessory software, TUI Viewer terminal.

----

# What Vuls Doesn't Do

- Vuls doesn't update the vulnerable packages.

----

# Hello Vuls 

This tutorial will let you scan the vulnerabilities on the localhost with Vuls.   
This can be done in the following steps.  

1. Launch Amazon Linux
1. Enable to ssh from localhost
1. Install requirements
1. Deploy go-cve-dictionary
1. Deploy Vuls
1. Configuration
1. Prepare
1. Scan
1. TUI(Terminal-Based User Interface)

## Step1. Launch Amazon Linux

- We are using the old AMI (amzn-ami-hvm-2015.09.1.x86_64-gp2 - ami-383c1956) for this example
- Add the following to the cloud-init, to avoid auto-update at the first launch.

    ```
    #cloud-config
    repo_upgrade: none
    ```

    - [Q: How do I disable the automatic installation of critical and important security updates on initial launch?](https://aws.amazon.com/amazon-linux-ami/faqs/?nc1=h_ls)
    
## Step2. SSH setting

This is required to ssh to itself.

Create a keypair then append public key to authorized_keys
```bash
$ ssh-keygen -t rsa
$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
$ chmod 600 ~/.ssh/authorized_keys
```

## Step3. Install requirements

Vuls requires the following packages.

- SQLite3
- git v2
- gcc
- go v1.6
    - https://golang.org/doc/install

```bash
$ ssh ec2-user@52.100.100.100  -i ~/.ssh/private.pem
$ sudo yum -y install sqlite git gcc
$ wget https://storage.googleapis.com/golang/go1.6.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.6.linux-amd64.tar.gz
$ mkdir $HOME/go
```
Add these lines into /etc/profile.d/goenv.sh

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

Set the OS environment variable to current shell
```bash
$ source /etc/profile.d/goenv.sh
```

## Step4. Deploy [go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary)

go get

```bash
$ sudo mkdir /var/log/vuls
$ sudo chown ec2-user /var/log/vuls
$ sudo chmod 700 /var/log/vuls
$ go get github.com/kotakanbe/go-cve-dictionary
```

If an error occurred while go get, check the following points.
- Update Git
- try [deploying with glide](https://github.com/future-architect/vuls/blob/master/README.md#deploy-with-glide).

Fetch vulnerability data from NVD.  
It takes about 10 minutes (on AWS).  

```bash
$ for i in {2002..2016}; do go-cve-dictionary fetchnvd -years $i; done
... snip ...
$ ls -alh cve.sqlite3
-rw-r--r-- 1 ec2-user ec2-user 7.0M Mar 24 13:20 cve.sqlite3
```

## Step5. Deploy Vuls

Launch a new terminal and SSH to the ec2 instance.

go get
```
$ go get github.com/future-architect/vuls
```

If an error occurred while go get, check the following points.
- Update Git
- try [deploying with glide](https://github.com/future-architect/vuls/blob/master/README.md#deploy-with-glide).

## Step6. Config

Create a config file(TOML format).

```
$ cat config.toml
[servers]

[servers.172-31-4-82]
host         = "172.31.4.82"
port        = "22"
user        = "ec2-user"
keyPath     = "/home/ec2-user/.ssh/id_rsa"
```

## Step7. Setting up target servers for Vuls  

```
$ vuls prepare
```
see [Usage: Prepare](https://github.com/future-architect/vuls#usage-prepare)

## Step8. Start Scanning

```
$ vuls scan -cve-dictionary-dbpath=$PWD/cve.sqlite3
INFO[0000] Start scanning (config: /home/ec2-user/config.toml)
INFO[0000] Start scanning
INFO[0000] config: /home/ec2-user/config.toml
INFO[0000] cve-dictionary: /home/ec2-user/cve.sqlite3


... snip ...

172-31-4-82 (amazon 2015.09)
============================
CVE-2016-0494   10.0    Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle
                        Java SE 6u105, 7u91, and 8u66 and Java SE Embedded 8u65 allows remote attackers to
                        affect confidentiality, integrity, and availability via unknown vectors related to
                        2D.
... snip ...

CVE-2016-0494
-------------
Score           10.0 (High)
Vector          (AV:N/AC:L/Au:N/C:C/I:C/A:C)
Summary         Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105,
                7u91, and 8u66 and Java SE Embedded 8u65 allows remote attackers to affect confidentiality,
                integrity, and availability via unknown vectors related to 2D.
NVD             https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-0494
MITRE           https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-0494
CVE Details     http://www.cvedetails.com/cve/CVE-2016-0494
CVSS Claculator https://nvd.nist.gov/cvss/v2-calculator?name=CVE-2016-0494&vector=(AV:N/AC:L/Au:N/C:C/I:C/A:C)
RHEL-CVE        https://access.redhat.com/security/cve/CVE-2016-0494
ALAS-2016-643   https://alas.aws.amazon.com/ALAS-2016-643.html
Package/CPE     java-1.7.0-openjdk-1.7.0.91-2.6.2.2.63.amzn1 -> java-1.7.0-openjdk-1:1.7.0.95-2.6.4.0.65.amzn1

```

## Step9. TUI

Vuls has Terminal-Based User Interface to display the scan result.

```
$ vuls tui
```

![Vuls-TUI](img/hello-vuls-tui.png)


----

# Setup Vuls in a Docker Container

see https://github.com/future-architect/vuls/tree/master/setup/docker

----

# Architecture

![Vuls-Architecture](img/vuls-architecture.png)

## [go-cve-dictinary](https://github.com/kotakanbe/go-cve-dictionary)  
- Fetch vulnerability information from NVD and JVN(Japanese), then insert into SQLite3.

## Vuls
- Scan vulnerabilities on the servers via SSH and create a list of the CVE ID
  - To scan Docker containers, Vuls connect via ssh to the Docker host and then `docker exec` to the containers. So, no need to run sshd daemon on the containers.
- Fetch more detailed information of the detected CVE from go-cve-dictionary
- Insert scan result into SQLite3
- Send a report by Slack and Email
- Show the latest report on your terminal

![Vuls-Scan-Flow](img/vuls-scan-flow.png)

----

# Use Cases

## Scan all servers

![Vuls-Usecase1](img/vuls-usecase-elb-rails-rds-all.png)

## Scan a single server

web/app server in the same configuration under the load balancer

![Vuls-Usecase2](img/vuls-usecase-elb-rails-rds-single.png)

----

# Support OS

| Distribution|            Release |
|:------------|-------------------:|
| Ubuntu      |          12, 14, 16|
| Debian      |                7, 8|
| RHEL        |          4, 5, 6, 7|
| CentOS      |             5, 6, 7|
| Amazon Linux|                 All|
| FreeBSD     |                  10|

----


# Usage: Automatic Server Discovery

Discovery subcommand discovers active servers specified in CIDR range, then display the template of config file(TOML format) to terminal.

```
$ vuls discover -help
discover:
        discover 192.168.0.0/24
```

## Example

```
$ vuls discover 172.31.4.0/24
# Create config.toml using below and then ./vuls --config=/path/to/config.toml

[slack]
hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
channel      = "#channel-name"
#channel      = "${servername}"
iconEmoji    = ":ghost:"
authUser     = "username"
notifyUsers  = ["@username"]

[mail]
smtpAddr      = "smtp.gmail.com"
smtpPort      = "465"
user          = "username"
password      = "password"
from          = "from@address.com"
to            = ["to@address.com"]
cc            = ["cc@address.com"]
subjectPrefix = "[vuls]"

[default]
#port        = "22"
#user        = "username"
#keyPath     = "/home/username/.ssh/id_rsa"

[servers]

[servers.172-31-4-82]
host         = "172.31.4.82"
#port        = "22"
#user        = "root"
#keyPath     = "/home/username/.ssh/id_rsa"
#cpeNames = [
#  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
#]
#containers = ["${running}"]
```

You can customize your configuration using this template.

----

# Configuration

- Slack section
    ```
    [slack]
    hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
    channel      = "#channel-name"
    #channel      = "${servername}"
    iconEmoji    = ":ghost:"
    authUser     = "username"
    notifyUsers  = ["@username"]
    ```

    - hookURL : Incomming webhook's URL  
    - channel : channel name.  
    If you set `${servername}` to channel, the report will be sent to each channel.  
    In the following example, the report will be sent to the `#server1` and `#server2`.  
    Be sure to create these channels before scanning.
      ```
      [slack]
      channel      = "${servername}"
      ...snip...

      [servers]

      [servers.server1]
      host         = "172.31.4.82"
      ...snip...

      [servers.server2]
      host         = "172.31.4.83"
      ...snip...
      ```

    - iconEmoji: emoji
    - authUser: username of the slack team
    - notifyUsers: a list of Slack usernames to send Slack notifications.
      If you set `["@foo", "@bar"]` to notifyUsers, @foo @bar will be included in text.  
      So @foo, @bar can receive mobile push notifications on their smartphone.  

- Mail section
    ```
    [mail]
    smtpAddr      = "smtp.gmail.com"
    smtpPort      = "465"
    user          = "username"
    password      = "password"
    from          = "from@address.com"
    to            = ["to@address.com"]
    cc            = ["cc@address.com"]
    subjectPrefix = "[vuls]"
    ```

- Default section
    ```
    [default]
    #port        = "22"
    #user        = "username"
    #keyPath     = "/home/username/.ssh/id_rsa"
    #cpeNames = [
    #  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
    #]
    #containers = ["${running}"]
    ```
    Items of the default section will be used if not specified.

- servers section
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    #port        = "22"
    #user        = "root"
    #keyPath     = "/home/username/.ssh/id_rsa"
    #cpeNames = [
    #  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
    #]
    #containers = ["${running}"]
    ```

    You can overwrite the default value specified in default section.  

    Vuls supports two types of SSH. One is native go implementation. The other is external SSH command. For details, see [-ssh-external option](https://github.com/future-architect/vuls#-ssh-external-option)
    
    Multiple SSH authentication methods are supported.  
    - SSH agent
    - SSH public key authentication (with password, empty password)
    - Password authentication



----

# Usage: Prepare

Prepare subcommand installs required packages on each server.

| Distribution|            Release | Requirements |
|:------------|-------------------:|:-------------|
| Ubuntu      |          12, 14, 16| -            |
| Debian      |                7, 8| aptitude     |
| CentOS      |                   5| yum-plugin-security, yum-changelog |
| CentOS      |                6, 7| yum-plugin-security, yum-plugin-changelog |
| Amazon      |                All | -            |
| RHEL        |         4, 5, 6, 7 | -            |
| FreeBSD     |                 10 | -            |


```
$ vuls prepare -help
prepare
                        [-config=/path/to/config.toml] [-debug]
                        [-ask-sudo-password]
                        [-ask-key-password]

  -ask-key-password
        Ask ssh privatekey password before scanning
  -ask-sudo-password
        Ask sudo password of target servers before scanning
  -config string
        /path/to/toml (default "$PWD/config.toml")
  -debug
        debug mode
  -use-unattended-upgrades
        [Deprecated] For Ubuntu, install unattended-upgrades
```

----

# Usage: Scan

```

$ vuls scan -help
scan:
        scan
                [-lang=en|ja]
                [-config=/path/to/config.toml]
                [-dbpath=/path/to/vuls.sqlite3]
                [--cve-dictionary-dbpath=/path/to/cve.sqlite3]
                [-cve-dictionary-url=http://127.0.0.1:1323]
                [-cvss-over=7]
                [-ignore-unscored-cves]
                [-ssh-external]
                [-report-json]
                [-report-mail]
                [-report-s3]
                [-report-slack]
                [-report-text]
                [-http-proxy=http://192.168.0.1:8080]
                [-ask-sudo-password]
                [-ask-key-password]
                [-debug]
                [-debug-sql]
                [-aws-profile=default]
                [-aws-region=us-west-2]
                [-aws-s3-bucket=bucket_name]

  -ask-key-password
        Ask ssh privatekey password before scanning
  -ask-sudo-password
        Ask sudo password of target servers before scanning
  -aws-profile string
        AWS Profile to use (default "default")
  -aws-region string
        AWS Region to use (default "us-east-1")
  -aws-s3-bucket string
        S3 bucket name
  -config string
        /path/to/toml (default "$PWD/config.toml")
  --cve-dictionary-dbpath string
        /path/to/sqlite3 (For get cve detail from cve.sqlite3)        
  -cve-dictionary-url string
        http://CVE.Dictionary (default "http://127.0.0.1:1323")
  -cvss-over float
        -cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))
  -dbpath string
        /path/to/sqlite3 (default "$PWD/vuls.sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -ignore-unscored-cves
        Don't report the unscored CVEs
  -lang string
        [en|ja] (default "en")
  -report-json
        Write report to JSON files ($PWD/results/current)
  -report-mail
        Send report via Email
  -report-s3
        Write report to S3 (bucket/yyyyMMdd_HHmm)
  -report-slack
        Send report via Slack
  -report-text
        Write report to text files ($PWD/results/current)
  -ssh-external
        Use external ssh command. Default: Use the Go native implementation
  -use-unattended-upgrades
        [Deprecated] For Ubuntu. Scan by unattended-upgrades or not (use apt-get upgrade --dry-run by default)
  -use-yum-plugin-security
        [Deprecated] For CentOS 5. Scan by yum-plugin-security or not (use yum check-update by default)

```

## -ssh-external option

Vuls supports different types of SSH.  

By Defaut, using a native Go implementation from crypto/ssh.   
This is useful in situations where you may not have access to traditional UNIX tools.

To use external ssh command, specify this option.   
This is useful If you want to use ProxyCommand or chiper algorithm of SSH that is not supported by native go implementation.  

## -ask-key-password option 

| SSH key password |  -ask-key-password | |
|:-----------------|:-------------------|:----|
| empty password   |                 -  | |
| with password    |           required | or use ssh-agent |

## -ask-sudo-password option

| sudo password on target servers | -ask-sudo-password | |
|:-----------------|:-------|:------|
| NOPASSWORD       | - | defined as NOPASSWORD in /etc/sudoers on target servers |
| with password    | required |  |


## -report-json , -report-text option

At the end of the scan, scan results will be available in the `$PWD/result/current/` directory.  
`all.(json|txt)` includes the scan results of all servres and `servername.(json|txt)` includes the scan result of the server.

## example

### Scan all servers defined in config file
```
$ vuls scan \
      --report-slack \ 
      --report-mail \
      --cvss-over=7 \
      -ask-sudo-password \ 
      -ask-key-password \
      -cve-dictionary-dbpath=$PWD/cve.sqlite3
```
With this sample command, it will ..
- Ask sudo password and ssh key passsword before scanning
- Scan all servers defined in config file
- Send scan results to slack and email
- Only Report CVEs that CVSS score is over 7
- Print scan result to terminal

### Scan specific servers
```
$ vuls scan \
      -cve-dictionary-dbpath=$PWD/cve.sqlite3 \ 
      server1 server2
```
With this sample command, it will ..
- Use SSH Key-Based authentication with empty password (without -ask-key-password option)
- Sudo with no password (without -ask-sudo-password option)
- Scan only 2 servers (server1, server2)
- Print scan result to terminal

### Put results in S3 bucket
To put results in S3 bucket, configure following settings in AWS before scanning.
- Create S3 bucket. see [Creating a Bucket](http://docs.aws.amazon.com/AmazonS3/latest/UG/CreatingaBucket.html)  
- Create access key. The access key must have read and write access to the AWS S3 bucket. see [Managing Access Keys for IAM Users](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- Configure the security credentials. see [Configuring the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

```
$ vuls scan \
      -cve-dictionary-dbpath=$PWD/cve.sqlite3 \ 
      -aws-region=ap-northeast-1 \
      -aws-s3-bucket=vuls \
      -aws-profile=default 
```
With this sample command, it will ..
- Use SSH Key-Based authentication with empty password (without -ask-key-password option)
- Sudo with no password (without -ask-sudo-password option)
- Scan all servers defined in config file
- Put scan result(JSON) in S3 bucket. The bucket name is "vuls" in ap-northeast-1 and profile is "default"


----

# Usage: Scan vulnerability of non-OS package

It is possible to detect vulnerabilities in non-OS packages, such as something you compiled by yourself, language libraries and frameworks, that have been registered in the [CPE](https://nvd.nist.gov/cpe.cfm).

-  How to search CPE name by software name
    - [NVD: Search Common Platform Enumerations (CPE)](https://web.nvd.nist.gov/view/cpe/search)  
    **Check CPE Naming Format: 2.2**

    - [go-cpe-dictionary](https://github.com/kotakanbe/go-cpe-dictionary) is a good choice for geeks.   
    You can search a CPE name by the application name incremenally.

- Configuration  
To detect the vulnerbility of Ruby on Rails v4.2.1, cpeNames needs to be set in the servers section.
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    user        = "ec2-user"
    keyPath     = "/home/username/.ssh/id_rsa"
    cpeNames = [
      "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
    ]
    ```
    
# Usage: Scan Docker containers

It is common that keep Docker containers runnning without SSHd daemon.  
see [Docker Blog:Why you don't need to run SSHd in your Docker containers](https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/)

Vuls scans Docker containers via `docker exec` instead of SSH.  
For more details, see [Architecture section](https://github.com/future-architect/vuls#architecture)

- To scan all of running containers  
  `"${running}"` needs to be set in the containers item.
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    user        = "ec2-user"
    keyPath     = "/home/username/.ssh/id_rsa"
    containers = ["${running}"]
    ```

- To scan specific containers  
  The container ID or container name needs to be set in the containers item.  
  In the following example, only `container_name_a` and `4aa37a8b63b9` will be scanned.  
  Be sure to check these containers are running state before scanning.  
  If specified containers are not running, Vuls gives up scanning with printing error message.
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    user        = "ec2-user"
    keyPath     = "/home/username/.ssh/id_rsa"
    containers = ["container_name_a", "4aa37a8b63b9"]
    ```

# Usage: TUI

## Display the latest scan results

```
$ vuls tui -h
tui:
	tui [-dbpath=/path/to/vuls.sqlite3]

  -dbpath string
        /path/to/sqlite3 (default "$PWD/vuls.sqlite3")
  -debug-sql
    	debug SQL

```

Key binding is bellow.

| key | |
|:-----------------|:-------|:------|
| TAB | move cursor among the panes |
| Arrow up/down | move cursor to up/down |
| Ctrl+j, Ctrl+k | move cursor to up/donw |
| Ctrl+u, Ctrl+d | page up/donw |

For details, see https://github.com/future-architect/vuls/blob/master/report/tui.go

## Display the previous scan results

- Display the list of scan results.
```
$ ./vuls history
2   2016-05-24 19:49 scanned 1 servers: amazon2
1   2016-05-24 19:48 scanned 2 servers: amazon1, romantic_goldberg
```

- Display the result of scanID 1
```
$ ./vuls tui 1
```

- Display the result of scanID 2
```
$ ./vuls tui 2
```

# Display the previous scan results using peco

```
$ ./vuls history | peco | ./vuls tui
```

[![asciicast](https://asciinema.org/a/emi7y7docxr60bq080z10t7v8.png)](https://asciinema.org/a/emi7y7docxr60bq080z10t7v8)

# Usage: go-cve-dictionary on different server 

Run go-cve-dictionary as server mode before scanning on 192.168.10.1
```
$ go-cve-dictionary server -bind=192.168.10.1 -port=1323
```

Run Vuls with -cve-dictionary-url option.

```
$ vuls scan -cve-dictionary-url=http://192.168.0.1:1323
```

# Usage: Update NVD Data

```
$ go-cve-dictionary fetchnvd -h
fetchnvd:
        fetchnvd
                [-last2y]
                [-dbpath=/path/to/cve.sqlite3]
                [-debug]
                [-debug-sql]

  -dbpath string
        /path/to/sqlite3 (default "$PWD/cve.sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -last2y
        Refresh NVD data in the last two years.
```

- Fetch data of the entire period

```
$ go-cve-dictionary fetchnvd -entire
```

- Fetch data in the last 2 years

```
$ go-cve-dictionary fetchnvd -last2y
```

----

# Deploy With Glide

If an error occurred while go get, try deploying with glide.  
- Install [Glide](https://github.com/bumptech/glide)
- Deploy go-cve-dictionary
```
$ go get -d github.com/kotakanbe/go-cve-dictionary
$ cd $GOPATH/src/github.com/kotakanbe/go-cve-dictionary
$ glide install
$ go install
```
- Deploy vuls
```
$ go get -d github.com/future-architect/vuls
$ cd $GOPATH/src/github.com/future-architect/vuls
$ glide install
$ go install
```
- The binaries are created under $GOPARH/bin

----

# Update Vuls With Glide

- Update go-cve-dictionary
```
$ cd $GOPATH/src/github.com/kotakanbe/go-cve-dictionary
$ git pull
$ glide install
$ go install
```

- Update vuls
```
$ cd $GOPATH/src/github.com/future-architect/vuls
$ git pull
$ glide install
$ go install
```
- The binaries are created under $GOPARH/bin
- If the DB schema was changed, please specify new SQLite3 DB file.

---

# Misc

- Unable to go get vuls  
Update git to the latest version. Old version of git can't get some repositories.  
see https://groups.google.com/forum/#!topic/mgo-users/rO1-gUDFo_g

- HTTP Proxy Support  
If your system is behind HTTP proxy, you have to specify --http-proxy option.

- How to Daemonize go-cve-dictionary  
Use Systemd, Upstart or supervisord, daemontools...

- How to Enable Automatic-Update of Vunerability Data.  
Use job scheduler like Cron (with -last2y option).

- How to Enable Automatic-Scan.  
Use job scheduler like Cron.  
Set NOPASSWORD option in /etc/sudoers on target servers.  
Use SSH Key-Based Authentication with no passphrase or ssh-agent.

- How to cross compile
    ```bash
    $ cd /path/to/your/local-git-reporsitory/vuls
    $ GOOS=linux GOARCH=amd64 go build -o vuls.amd64
    ```

- Logging  
Log is under /var/log/vuls/

- Debug  
Run with --debug, --sql-debug option.

- Adjusting Open File Limit  
[Riak docs](http://docs.basho.com/riak/latest/ops/tuning/open-files-limit/) is awesome.

- Does Vuls accept ssh connections with fish-shell or old zsh as the login shell?  
No, Vuls needs a user on the server for bash login. see also [#8](/../../issues/8)

- Windows  
Use Microsoft Baseline Security Analyzer. [MBSA](https://technet.microsoft.com/en-us/security/cc184924.aspx)

----

# Related Projects 

- [k1LoW/ssh_config_to_vuls_config](https://github.com/k1LoW/ssh_config_to_vuls_config)   
ssh_config to vuls config TOML format

- [usiusi360/vulsrepo](https://github.com/usiusi360/vulsrepo)  
VulsRepo is visualized based on the json report output in vuls.  
Youtube  
[![vulsrepo](http://img.youtube.com/vi/DIBPoik4owc/0.jpg)](https://www.youtube.com/watch?v=DIBPoik4owc)


----

# Data Source

- [NVD](https://nvd.nist.gov/)
- [JVN(Japanese)](http://jvndb.jvn.jp/apis/myjvn/)


# Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created vuls and [these fine people](https://github.com/future-architect/vuls/graphs/contributors) have contributed.

----

# Contribute

1. fork a repository: github.com/future-architect/vuls to github.com/you/repo
2. get original code: go get github.com/future-architect/vuls
3. work on original code
4. add remote to your repo: git remote add myfork https://github.com/you/repo.git
5. push your changes: git push myfork
6. create a new Pull Request

- see [GitHub and Go: forking, pull requests, and go-getting](http://blog.campoy.cat/2014/03/github-and-go-forking-pull-requests-and.html)

----

# Change Log

Please see [CHANGELOG](https://github.com/future-architect/vuls/blob/master/CHANGELOG.md).

----

# Licence

Please see [LICENSE](https://github.com/future-architect/vuls/blob/master/LICENSE).


