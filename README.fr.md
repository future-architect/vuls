
# Vuls: VULnerability Scanner

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](http://goo.gl/forms/xm5KFo35tu)

Scanneur de vulnérabilité Linux, sans agent, écrit en golang

Nous avons une équipe Slack. [Rejoignez notre Slack Team](http://goo.gl/forms/xm5KFo35tu)  

[README en Japonais](https://github.com/future-architect/vuls/blob/master/README.ja.md)  

[![asciicast](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck.png)](https://asciinema.org/a/3y9zrf950agiko7klg8abvyck)

![Vuls-slack](img/vuls-slack-en.png)



----

# Résumé

Effectuer des recherches de vulnérabilités et des mises à jour quotidiennes peut etre un fardeau pour un administrateur système.
Afin d'éviter des interruptions systèmes dans un environnement de production, il est fréquent pour un administrateur système de choisir de ne pas utiliser la fonction de mise à jour automatique proposée par le gestionnaire de paquets et d'effecter ces mises à jour manuellement.
Ce qui implique les problèmes suivants :
- L'administrateur système devra surveiller constamment toutes les nouvelles vulnérabilités dans NVD (National Vulnerability Database) etc.
- Il pourrait être impossible pour un administrateur système de surveiller tous les logiciels installés sur un serveur.
- Il est coûteux d'effectuer une analyse pour déterminer quels sont les serveurs affectés par de nouvelles vulnérabilités. La possibilité de négliger un serveur ou deux est bien présente.

Vuls est un outil crée pour palier aux problèmes listés ci-dessus. Voici ces caractéristiques.
- Informer les utilisateurs des vulnérabilités système.
- Informer les utilisateurs des systèmes concernés. 
- La détection de vulnérabilités est effectuée automatiquement pour éviter toute négligence.
- Les rapports sont générés régulièrement via CRON pour mieux gérer ces vulnérabilités.

![Vuls-Motivation](img/vuls-motivation.png)

----

# Caractéristiques principales

- Recherche de vulnérabilités sur des serveurs Linux
    - Supporte Ubuntu, Debian, CentOS, Amazon Linux, RHEL
    - Cloud, auto-hébergement, Docker
- Scan d'intergiciels non inclus dans le gestionnaire de paquets de l'OS
    - Scan d'intergiciels, de libraries de language de programmation et framework pour des vulnérabilités
    - Supporte les logiciels inscrits sur CPE
- Architecture sans agent
    - L'utilisateur doit seulement mettre en place VULS sur une seule machine qui se connectera aux autres via SSH
- Génération automatique des fichiers de configuration
    - Auto detection de serveurs via CIDR et génération de configuration
- Email et notification Slack possibles (supporte le Japonais) 
- Les résultats d'un scan sont accessibles dans un shell via TUI Viewer terminal.

----

# Ce que Vuls ne fait pas

- Vuls ne met pas à jour les programmes affectés par les vulnérabilités découvertes.

----

# Hello Vuls 

Ce tutoriel décrit la recherche de vulnérabilités sur une machine locale avec Vuls.
Voici les étapes à suivre. 

1. Démrarrage d'Amazon Linux
1. Autoriser les connexions SSH depuis localhost
1. Installation des prérequis
1. Déploiement de go-cve-dictionary
1. Deploiement de Vuls
1. Configuration
1. Préparation
1. Scan
1. TUI(Terminal-Based User Interface)

## Step1. Démrarrage d'Amazon Linux

- Nous utilisons dans cette exemple une vieille AMI (amzn-ami-hvm-2015.09.1.x86_64-gp2 - ami-383c1956)
- Taille de l'instance : t2.medium
    - La première fois, t2.medium et plus sont requis pour la récupération des CVE depuis NVD (2.3GB de mémoire utilisé)
    - Une fois la récupération initiale des données NVD terminée vous pouvez passer sur une instance t2.nano.
- Ajoutez la configuration suivante au cloud-init, afin d'éviter une mise à jour automatique lors du premier démarrage.

    - [Q: How do I disable the automatic installation of critical and important security updates on initial launch?](https://aws.amazon.com/amazon-linux-ami/faqs/?nc1=h_ls)
    ```
    #cloud-config
    repo_upgrade: none
    ```

## Step2. Paramètres SSH

Il est obligatoire que le serveur puisse se connecter à son propre serveur SSH

Générez une paire de clés SSH et ajoutez la clé publique dans le fichier authorized_keys
```bash
$ ssh-keygen -t rsa
$ cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
$ chmod 600 ~/.ssh/authorized_keys
```

## Step3. Installation des prérequis

Vuls requiert l'installation des paquets suivants : 

- sqlite
- git
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
Ajoutez les lignes suivantes dans /etc/profile.d/goenv.sh

```bash
export GOROOT=/usr/local/go
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

Ajoutons ces nouvelles variables d’environnement au shell
```bash
$ source /etc/profile.d/goenv.sh
```

## Step4. Déploiement de [go-cve-dictionary](https://github.com/kotakanbe/go-cve-dictionary)

go get

```bash
$ sudo mkdir /var/log/vuls
$ sudo chown ec2-user /var/log/vuls
$ sudo chmod 700 /var/log/vuls
$ go get github.com/kotakanbe/go-cve-dictionary
```

Démarrez go-cve-dictionary en mode serveur.
Lors de son premier démarrage go-cve-dictionary récupère la liste des vulnérabilités depuis NVD
Cette opération prend environ 10 minutes (sur AWS).  

```bash
$ go-cve-dictionary server
... Fetching ...
$ ls -alh cve.sqlite3
-rw-r--r-- 1 ec2-user ec2-user 7.0M Mar 24 13:20 cve.sqlite3
```

Une fois les informations de vulnérabilités collectées redémarrez le mode serveur.
```bash
$ go-cve-dictionary server
[Mar 24 15:21:55]  INFO Opening DB. datafile: /home/ec2-user/cve.sqlite3
[Mar 24 15:21:55]  INFO Migrating DB
[Mar 24 15:21:56]  INFO Starting HTTP Sever...
[Mar 24 15:21:56]  INFO Listening on 127.0.0.1:1323
```

## Step5. Déploiement de Vuls

Ouvrez un second terminal, connectez vous à l'instance ec2 via SSH

go get
```
$ go get github.com/future-architect/vuls
```

## Step6. Configuration

Créez un fichier de configuration (TOML format).

```
$ cat config.toml
[servers]

[servers.172-31-4-82]
host         = "172.31.4.82"
port        = "22"
user        = "ec2-user"
keyPath     = "/home/ec2-user/.ssh/id_rsa"
```

## Step7. Configuration des serveurs cibles vuls  

```
$ vuls prepare
```

## Step8. Scan

```
$ vuls scan
INFO[0000] Begin scanning (config: /home/ec2-user/config.toml)

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

Les résultats de Vuls peuvent etre affichés dans un Shell via TUI (Terminal-Based User Interface).

```
$ vuls tui
```

![Vuls-TUI](img/hello-vuls-tui.png)


----

# Architecture

![Vuls-Architecture](img/vuls-architecture.png)

## go-cve-dictinary  
- Collecte les données de vulnérabilités depuis NVD, JVN(Japonais), et les envoient dans SQLite.

## Vuls
- Scan de vulnérabilités sur serveurs et création d'une liste contenant les CVE ID
- Pour des informations plus détaillés sur une CVE, envoie une requete HTTP à go-cve-dictinary 
- Rapport via Slack, Email
- L'administrateur système peut voir les résultats du dernier rapport dans le terminal

----

# Exemples d'utilisation

## Scan de tous les serverus

![Vuls-Usecase1](img/vuls-usecase-elb-rails-rds-all.png)

## Scan d'un seul serveur

web/app server in the same configuration under the load balancer

![Vuls-Usecase2](img/vuls-usecase-elb-rails-rds-single.png)

----

# OS supportés 

| Distribution|            Release |
|:------------|-------------------:|
| Ubuntu      |          12, 14, 16|
| Debian      |                7, 8|
| RHEL        |          4, 5, 6, 7|
| CentOS      |             5, 6, 7|
| Amazon Linux|                All |

----


# Usage: Détection Automatique de Serveurs 

La sous-commande Discovery permet de détecter les serveurs actifs dans un range d'IP CIDR, les résultas sont directement affichés dans le terminal en respectant le format du fichier de configuration (TOML format).

```
$ vuls discover -help
discover:
        discover 192.168.0.0/24
```

## Exemple

```
$ vuls discover 172.31.4.0/24
# Create config.toml using below and then ./vuls --config=/path/to/config.toml

[slack]
hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
channel      = "#channel-name"
#channel      = "#{servername}"
iconEmoji    = ":ghost:"
authUser     = "username"
notifyUsers  = ["@username"]

[mail]
smtpAddr      = "smtp.gmail.com"
smtpPort      = 465
user          = "username"
password      = "password"
from          = "from@address.com"
to            = ["to@address.com"]
cc            = ["cc@address.com"]
subjectPrefix = "[vuls]"

[default]
#port        = "22"
#user        = "username"
#password    = "password"
#keyPath     = "/home/username/.ssh/id_rsa"
#keyPassword = "password"

[servers]

[servers.172-31-4-82]
host         = "172.31.4.82"
#port        = "22"
#user        = "root"
#password    = "password"
#keyPath     = "/home/username/.ssh/id_rsa"
#keyPassword = "password"
#cpeNames = [
#  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
#]
```

Vous pouvez customiser votre configuration en utilisant ce modèle.

----

# Configuration

- Slack section
    ```
    [slack]
    hookURL      = "https://hooks.slack.com/services/abc123/defghijklmnopqrstuvwxyz"
    channel      = "#channel-name"
    #channel      = "#{servername}"
    iconEmoji    = ":ghost:"
    authUser     = "username"
    notifyUsers  = ["@username"]
    ```

    - hookURL : Incomming webhook's URL  
    - channel : channel name.  
    If you set #{servername} to channel, the report will be sent to #servername channel.  
    In the following example, the report will be sent to the #server1 and #server2.  
    Be sure to create these channels before scanning.
      ```
      [slack]
      channel      = "#{servername}"
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
      If you set ["@foo", "@bar"] to notifyUsers, @foo @bar will be included in text.  
      So @foo, @bar can receive mobile push notifications on their smartphone.  

- Mail section
    ```
    [mail]
    smtpAddr      = "smtp.gmail.com"
    smtpPort      = 465
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
    #password    = "password"
    #keyPath     = "/home/username/.ssh/id_rsa"
    #keyPassword = "password"
    ```
    Items of the default section will be used if not specified.

- servers section
    ```
    [servers]

    [servers.172-31-4-82]
    host         = "172.31.4.82"
    #port        = "22"
    #user        = "root"
    #password    = "password"
    #keyPath     = "/home/username/.ssh/id_rsa"
    #keyPassword = "password"
    #cpeNames = [
    #  "cpe:/a:rubyonrails:ruby_on_rails:4.2.1",
    #]
    ```
    Vous pouvez remplacer les valeurs par défaut indiquées en modifiant la section default
    Vuls supporte plusieurs méthodes d'authentification SSH :
    - SSH agent
    - SSH authentication par clés (avec mot de passe ou sans mot de passe)
    - Authentification par mot de passe

----

# Usage : Prepare

La sous-commande prepare installe tous les paquets nécessaires sur chaque serveur.

| Distribution|            Release | Requirements |
|:------------|-------------------:|:-------------|
| Ubuntu      |          12, 14, 16| -            |
| Debian      |                7, 8| apptitude    |
| CentOS      |                   5| yum-plugin-security, yum-changelog |
| CentOS      |                6, 7| yum-plugin-security, yum-plugin-changelog |
| Amazon      |                All | -            |
| RHEL        |         4, 5, 6, 7 | -            |


```
$ vuls prepare -help
prepare:
        prepare [-config=/path/to/config.toml] [-debug]

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
                [-cve-dictionary-url=http://127.0.0.1:1323]
                [-cvss-over=7]
                [-report-slack]
                [-report-mail]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
  -config string
        /path/to/toml (default "$PWD/config.toml")
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
  -lang string
        [en|ja] (default "en")
  -report-mail
        Email report
  -report-slack
        Slack report
  -use-unattended-upgrades
        [Deprecated] For Ubuntu. Scan by unattended-upgrades or not (use apt-get upgrade --dry-run by default)
  -use-yum-plugin-security
        [Deprecated] For CentOS 5. Scan by yum-plugin-security or not (use yum check-update by default)

```

## example

Lancez go-cve-dictionary en mode serveur avant de lancer un scan
```
$ go-cve-dictionary server
```

### Scan tous les serveurs identifiés dans le fichier de configuration
```
$ vuls scan --report-slack --report-mail --cvss-over=7
```
Via cette simple commande Vuls va : ..
- Scanner tous les serveurs identifiés dans le fichier de configuration
- Envoyer les résultas du scan à slack et par email
- Ne rapporter que les CVE dont la note CVSS est au dessus de 7
- Afficher les résultats du scan dans le terminal

### Scan de serveurs spécifiques
```
$ vuls scan server1 server2
```
Via cette simple commande Vuls va : ..
- Scanner seulement 2 serveurs. (server1, server2)
- Afficher les résultats du scan dans le terminal

----

# Usage: Scan vulnerability of non-OS package

It is possible to detect vulnerabilities something you compiled by yourself, the language libraries and the frameworks that have been registered in the [CPE](https://nvd.nist.gov/cpe.cfm).

-  How to search CPE name by software name
    - [NVD: Search Common Platform Enumerations (CPE)](https://web.nvd.nist.gov/view/cpe/search)  
    **Check CPE Naming Format: 2.2**

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

# Usage: Update NVD Data.

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

# Misc

- HTTP Proxy Support  
If your system is behind HTTP proxy, you have to specify --http-proxy option.

- How to Daemonize go-cve-dictionary  
Use Systemd, Upstart or supervisord, daemontools...

- How to Enable Automatic-Update of Vunerability Data.  
Use job scheduler like Cron (with -last2y option).

- How to cross compile
    ```bash
    $ cd /path/to/your/local-git-reporsitory/vuls
    $ GOOS=linux GOARCH=amd64 go build -o vuls.amd64
    ```

- Logging  
Log wrote to under /var/log/vuls/

- Debug  
Run with --debug, --sql-debug option.

- Ajusting Open File Limit  
[Riak docs](http://docs.basho.com/riak/latest/ops/tuning/open-files-limit/) is awesome.

- Does Vuls accept ssh connections with fish-shell or old zsh as the login shell?  
No, Vuls needs a user on the server for bash login. see also [#8](/../../issues/8)

- Windows  
Use Microsoft Baseline Security Analyzer. [MBSA](https://technet.microsoft.com/en-us/security/cc184924.aspx)

----

# Data Source

- [NVD](https://nvd.nist.gov/)
- [JVN(Japanese)](http://jvndb.jvn.jp/apis/myjvn/)


# Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created vuls and [these fine people](https://github.com/future-architect/vuls/graphs/contributors) have contributed.

----

# Contribute

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

----

# Change Log

Please see [CHANGELOG](https://github.com/future-architect/vuls/blob/master/CHANGELOG.md).

----

# Licence

Please see [LICENSE](https://github.com/future-architect/vuls/blob/master/LICENSE).


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/future-architect/vuls/trend.png)](https://bitdeli.com/free "Bitdeli Badge")


