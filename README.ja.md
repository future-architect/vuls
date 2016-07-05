
# Vuls: VULnerability Scanner

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](http://goo.gl/forms/xm5KFo35tu)

Vulnerability scanner for Linux/FreeBSD, agentless, written in golang.

[README in English](https://github.com/future-architect/vuls/blob/master/README.md)  
Slackチームは[こちらから](http://goo.gl/forms/xm5KFo35tu)参加できます。(日本語でオッケーです)

[![asciicast](https://asciinema.org/a/bazozlxrw1wtxfu9yojyihick.png)](https://asciinema.org/a/bazozlxrw1wtxfu9yojyihick)

![Vuls-slack](img/vuls-slack-ja.png)

----

# Abstract

毎日のように発見される脆弱性の調査やソフトウェアアップデート作業は、システム管理者にとって負荷の高いタスクである。
プロダクション環境ではサービス停止リスクを避けるために、パッケージマネージャの自動更新機能を使わずに手動更新で運用するケースも多い。
だが、手動更新での運用には以下の問題がある。
- システム管理者がNVDなどで新着の脆弱性をウォッチし続けなければならない
- サーバにインストールされているソフトウェアは膨大であり、システム管理者が全てを把握するのは困難
- 新着の脆弱性がどのサーバに該当するのかといった調査コストが大きく、漏れる可能性がある


Vulsは上に挙げた手動運用での課題を解決するツールであり、以下の特徴がある。
- システムに関係ある脆弱性のみ教えてくれる
- その脆弱性に該当するサーバを教えてくれる
- 自動スキャンのため脆弱性検知の漏れを防ぐことができる
- CRONなどで定期実行、レポートすることで脆弱性の放置を防ぐことできる

![Vuls-Motivation](img/vuls-motivation.png)

----

# Main Features

- Linuxサーバに存在する脆弱性をスキャン
    - Ubuntu, Debian, CentOS, Amazon Linux, RHELに対応
    - クラウド、オンプレミス、Docker
- OSパッケージ管理対象外のミドルウェアをスキャン
    - プログラミング言語のライブラリやフレームワーク、ミドルウェアの脆弱性スキャン
    - CPEに登録されているソフトウェアが対象
- エージェントレスアーキテクチャ
    - スキャン対象サーバにSSH接続可能なマシン1台にセットアップするだけで動作
- 設定ファイルのテンプレート自動生成
    - CIDRを指定してサーバを自動検出、設定ファイルのテンプレートを生成
- EmailやSlackで通知可能（日本語でのレポートも可能）
- 付属するTerminal-Based User Interfaceビューアでは、Vim風キーバインドでスキャン結果を参照可能

----

# What Vuls Doesn't Do

- Vulsはソフトウェアアップデートは行わない

----

# Hello Vuls 

本チュートリアルでは、Amazon EC2にVulsをセットアップし、自分に存在する脆弱性をスキャンする方法を説明する。
手順は以下の通り

1. Amazon Linuxを新規作成
1. 自分自身にSSH接続できるように設定
1. 必要なソフトウェアをインストール
1. go-cve-dictionaryをデプロイ
1. Vulsをデプロイ
1. 設定
1. Prepare
1. Scan
1. TUI(Terminal-Based User Interface)で結果を参照する

## Step1. Launch Amazon Linux

- 今回は説明のために、脆弱性を含む古いAMIを使う (amzn-ami-hvm-2015.09.1.x86_64-gp2 - ami-383c1956)
- EC2作成時に自動アップデートされるとVulsスキャン結果が0件になってしまうので、cloud-initに以下を指定してEC2を作成する。

    ```
    #cloud-config
    repo_upgrade: none
    ```

    - [Q: How do I disable the automatic installation of critical and important security updates on initial launch?](https://aws.amazon.com/amazon-linux-ami/faqs/?nc1=h_ls)

## Step2. SSH setting

ローカルホストにSSH接続できるようにする。

SSHキーペアを作成し、公開鍵をauthorized_keysに追加する。
```bash
$ ssh-keygen -t rsa
$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
$ chmod 600 ~/.ssh/authorized_keys
```

## Step3. Install requirements

Vulsセットアップに必要な以下のソフトウェアをインストールする。

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
/etc/profile.d/goenv.sh を作成し、下記を追加する。 

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

カレントシェルに上記環境変数をセットする。
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

go getでエラーが発生した場合は、以下の点を確認する。
- Gitのバージョンがv2以降か？
- Go依存パッケージの問題でgo getに失敗する場合は [deploying with glide](https://github.com/future-architect/vuls/blob/master/README.md#deploy-with-glide) を試す。

NVDから脆弱性データベースを取得する。  
環境によって異なるが、AWS上では10分程度かかる。

```bash
$ for i in {2002..2016}; do go-cve-dictionary fetchnvd -years $i; done
... snip ...
$ ls -alh cve.sqlite3
-rw-r--r-- 1 ec2-user ec2-user 7.0M Mar 24 13:20 cve.sqlite3
```

## Step5. Deploy Vuls

新規にターミナルを起動し、先ほど作成したEC2にSSH接続する。

go get
```
$ go get github.com/future-architect/vuls
```

go getでエラーが発生した場合は、以下の点を確認する。
- Gitのバージョンがv2以降か？
- Go依存パッケージの問題でgo getに失敗する場合は [deploying with glide](https://github.com/future-architect/vuls/blob/master/README.md#deploy-with-glide) を試す。

## Step6. Config

Vulの設定ファイルを作成する（TOMLフォーマット）

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
詳細は [Usage: Prepare](https://github.com/future-architect/vuls#usage-prepare) を参照

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

Vulsにはスキャン結果の詳細を参照できるイカしたTUI(Terminal-Based User Interface)が付属している。

```
$ vuls tui
```

![Vuls-TUI](img/hello-vuls-tui.png)


----

# Setup Vuls in a Docker Container

VulsをDockerコンテナ上に作成する方法  
see https://github.com/future-architect/vuls/tree/master/setup/docker

----

# Architecture

![Vuls-Architecture](img/vuls-architecture.png)

## [go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary)  
- NVDとJVN(日本語)から脆弱性データベースを取得し、SQLite3に格納する。

## Vuls
- SSHでサーバに存在する脆弱性をスキャンし、CVE IDのリストを作成する
  - Dockerコンテナのスキャンする場合、VulsはまずDockerホストにSSHで接続する。その後、Dockerホスト上で `docker exec` 経由でコマンドを実効する。Dockerコンテナ内にSSHデーモンを起動する必要はない
- 検出されたCVEの詳細情報をgo-cve-dictionaryから取得する
- スキャン結果をSQLite3に格納する
- スキャン結果レポートを生成し、SlackやEmailなどで送信する
- スキャン結果の詳細情報はターミナル上で参照可能

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

Discoveryサブコマンドは指定されたCIDRレンジ内でpingが返ってくるサーバを発見して、ターミナル上にVulsの設定ファイルのテンプレートを出力する。

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

このテンプレート使ってVulsの設定フィアルを作ってもよい。

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
    channelに`${servername}`を指定すると、結果レポートをサーバごとに別チャネルにすることが出来る。
    以下のサンプルでは、`#server1`チャネルと`#server2`チャネルに送信される。スキャン前にチャネルを作成する必要がある。
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
    - notifyUsers: ここにユーザ名を指定すると、Slackで通知を受け取ることができる。たとえば `["@foo", "@bar"]`を指定すると、Slackのテキストに`@foo`と`@bar`が含まれるのでスマホなどにPush通知が可能。

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
    下記serversセクションで値が指定されなかった場合のデフォルト値

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

    serversセクションの値は、defaultセクションの値よりも優先される。
    defaultセクションの値を使いたい場合は `#` でコメントアウトする。

    Vulsは各サーバにSSHで接続するが、Goのネイティブ実装と、OSコマンドの２種類のSSH接続方法をサポートしている。
    詳細は [-ssh-external option](https://github.com/future-architect/vuls#-ssh-external-option) を参照。
    
    また、以下のSSH認証をサポートしている。
    - SSH agent
    - SSH public key authentication (with password, empty password)
    - Password authentication


----

# Usage: Prepare

Prepareサブコマンドは、Vuls内部で利用する以下のパッケージをスキャン対象サーバにインストーする。

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

Vulsは２種類のSSH接続方法をサポートしている。

デフォルトでは、Goのネイティブ実装 (crypto/ssh) を使ってスキャンする。 
これは、SSHコマンドがインストールされていない環境でも動作する（Windowsなど）  

外部SSHコマンドを使ってスキャンするためには、`-ssh-external`を指定する。
SSH Configが使えるので、ProxyCommandを使った多段SSHなどが可能。

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

結果をファイルに出力したい場合に指定する。出力先は、`$PWD/result/current/`    
`all.(json|txt)`には、全サーバのスキャン結果が出力される。  
`servername.(json|txt)`には、サーバごとのスキャン結果が出力される。

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
この例では、
- スキャン対象サーバのsudoパスワードを指定
- SSH公開鍵認証（秘密鍵パスフレーズ）を指定
- configに定義された全サーバをスキャン
- レポートをslack, emailに送信
- CVSSスコアが 7.0 以上の脆弱性のみレポート
- go-cve-dictionaryにはHTTPではなくDBに直接アクセス（go-cve-dictionaryをサーバモードで起動しない）

### Scan specific servers
```
$ vuls scan \
      -cve-dictionary-dbpath=$PWD/cve.sqlite3 \ 
      server1 server2
```
この例では、
- SSH公開鍵認証（秘密鍵パスフレーズなし）
- ノーパスワードでsudoが実行可能
- configで定義されているサーバの中の、server1, server2のみスキャン

### Put results in S3 bucket
レポートをS3バケットに格納する方法

事前にAWS関連の設定を行う
- S3バケットを作成 [Creating a Bucket](http://docs.aws.amazon.com/AmazonS3/latest/UG/CreatingaBucket.html)
- アクセスキーを作成し、S3バケットへのREAD/WRITE権限をつけておく [Managing Access Keys for IAM Users](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
- security credentialsを設定 [Configuring the AWS Command Line Interface](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)

```
$ vuls scan \
      -cve-dictionary-dbpath=$PWD/cve.sqlite3 \ 
      -aws-region=ap-northeast-1 \
      -aws-s3-bucket=vuls \
      -aws-profile=default 
```
この例では、
- SSH公開鍵認証（秘密鍵パスフレーズなし）
- ノーパスワードでsudoが実行可能
- configに定義された全サーバをスキャン
- 結果をJSON形式でS3に格納する。
  - バケット名 ... vuls
  - リージョン ... ap-northeast-1
  - 利用するProfile ... default

----

# Usage: Scan vulnerability of non-OS package

Vulsは、[CPE](https://nvd.nist.gov/cpe.cfm)に登録されているソフトウェアであれば、OSパッケージ以外のソフトウェアの脆弱性もスキャン可能。
たとえば、自分でコンパイルしたものや、言語のライブラリ、フレームワークなど。

-  CPEの検索方法
    - [NVD: Search Common Platform Enumerations (CPE)](https://web.nvd.nist.gov/view/cpe/search)  
    **Check CPE Naming Format: 2.2**

    - [go-cpe-dictionary](https://github.com/kotakanbe/go-cpe-dictionary) is a good choice for geeks.   
    ターミナル上でCPEをインクリメンタル検索出来るツール

- Configuration  
例えば、Ruby on Rails v4.2.1の脆弱性を検知したい場合は、serversセクションに以下のように定義する。
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

DockerコンテナはSSHデーモンを起動しないで運用するケースが一般的。  
 [Docker Blog:Why you don't need to run SSHd in your Docker containers](https://blog.docker.com/2014/06/why-you-dont-need-to-run-sshd-in-docker/)

Vulsは、DockerホストにSSHで接続し、`docker exec`でDockerコンテナにコマンドを発行して脆弱性をスキャンする。
詳細は、[Architecture section](https://github.com/future-architect/vuls#architecture)を参照

- 全ての起動中のDockerコンテナをスキャン  
  `"${running}"` をcontainersに指定する
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    user        = "ec2-user"
    keyPath     = "/home/username/.ssh/id_rsa"
    containers = ["${running}"]
    ```

- あるコンテナのみスキャン
  コンテナID、または、コンテナ名を、containersに指定する。
  以下の例では、`container_name_a`と、`4aa37a8b63b9`のコンテナのみスキャンする
  スキャン実行前に、コンテナが起動中か確認すること。もし起動してない場合はエラーメッセージを出力してスキャンを中断する。
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

# Usage: go-cve-dictonary on different server 

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

# レポートの日本語化

- JVNから日本語の脆弱性情報を取得
    ```
    $ go-cve-dictionary fetchjvn -help
    fetchjvn:
            fetchjvn [-dump-path=$PWD/cve] [-dpath=$PWD/vuls.sqlite3] [-week] [-month] [-entire]

      -dbpath string
            /path/to/sqlite3/DBfile (default "$PWD/cve.sqlite3")
      -debug
            debug mode
      -debug-sql
            SQL debug mode
      -dump-path string
            /path/to/dump.json (default "$PWD/cve.json")
      -entire
            Fetch data for entire period.(This operation is time-consuming) (default: false)
      -month
            Fetch data in the last month (default: false)
      -week
            Fetch data in the last week. (default: false)

    ```

- すべての期間の脆弱性情報を取得(1時間以上かかる)
    ```
    $ go-cve-dictionary fetchjvn -entire
    ```

- 直近1ヶ月間に更新された脆弱性情報を取得(1分未満)
    ```
    $ go-cve-dictionary fetchjvn -month
    ```

- 直近1週間に更新された脆弱性情報を取得(1分未満)
    ```
    $ go-cve-dictionary fetchjvn -week
    ```

- 脆弱性情報の自動アップデート  
Cronなどのジョブスケジューラを用いて実現可能。  
-week オプションを指定して夜間の日次実行を推奨。


## スキャン実行

```
$ vuls scan -lang=ja
```
Scan時にlang=jaを指定すると脆弱性レポートが日本語になる  
slack, emailは日本語対応済み TUIは日本語表示未対応

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

- go get時にエラーが出る  
Gitをv2にアップデートしてお試しを  
see https://groups.google.com/forum/#!topic/mgo-users/rO1-gUDFo_g

- HTTP Proxy サポート
プロキシ環境下では、-http-proxyオプションを指定

- go-cve-dictionaryのデーモン化  
Use Systemd, Upstart or supervisord, daemontools...

- NVD, JVNの脆弱性データベースの自動更新  
CRONなどを使えば可能

- 自動定期スキャン  
CRONなどを使い、自動化のためにsudoと、秘密鍵のパスワードなしでも実行可能なようにする
  - スキャン対象サーバの /etc/sudoers に NOPASSWORD を設定する  
  - 秘密鍵パスフレーズなしの公開鍵認証か、ssh-agentを使う  

- クロスコンパイル
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


