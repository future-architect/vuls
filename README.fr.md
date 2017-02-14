
# Vuls: VULnerability Scanner

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](http://goo.gl/forms/xm5KFo35tu)

Scanneur de vulnérabilité Linux, sans agent, écrit en golang

Nous avons une équipe Slack. [Rejoignez notre Slack Team](http://goo.gl/forms/xm5KFo35tu)  

[README en English](https://github.com/future-architect/vuls/blob/master/README.md)  
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

Vuls est un outil crée pour palier aux problèmes listés ci-dessus. Voici ses caractéristiques.
- Informer les utilisateurs des vulnérabilités système.
- Informer les utilisateurs des systèmes concernés. 
- La détection de vulnérabilités est effectuée automatiquement pour éviter toute négligence.
- Les rapports sont générés régulièrement via CRON pour mieux gérer ces vulnérabilités.

![Vuls-Motivation](img/vuls-motivation.png)

----

# Caractéristiques principales

- Recherche de vulnérabilités sur des serveurs Linux
    - Supporte Ubuntu, Debian, CentOS, Amazon Linux, RHEL, Raspbian
    - Cloud, auto-hébergement, Docker
- Scan d'intergiciels non inclus dans le gestionnaire de paquets de l'OS
    - Scan d'intergiciels, de libraries de language de programmation et framework pour des vulnérabilités
    - Supporte les logiciels inscrits au CPE
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
- go v1.7.1 or later
    - https://golang.org/doc/install

```bash
$ ssh ec2-user@52.100.100.100  -i ~/.ssh/private.pem
$ sudo yum -y install sqlite git gcc
$ wget https://storage.googleapis.com/golang/go1.7.1.linux-amd64.tar.gz
$ sudo tar -C /usr/local -xzf go1.7.1.linux-amd64.tar.gz
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
$ vuls scan -cve-dictionary-dbpath=$PWD/cve.sqlite3
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
CVSS Calculator https://nvd.nist.gov/cvss/v2-calculator?name=CVE-2016-0494&vector=(AV:N/AC:L/Au:N/C:C/I:C/A:C)
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

For more information see [README in English](https://github.com/future-architect/vuls/blob/master/README.md)  
