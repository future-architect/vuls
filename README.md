# Vuls: VULnerability Scanner

## NOTE
This is the nightly branch and provides the latest functionality. 
Please use the master branch if you want to use it stably, as destructive changes are also made.

## Usage

### 1. Nightly Vuls installation

```console
$ go install github.com/future-architect/vuls/cmd/vuls@nightly
$ vuls version
vuls nightly 2ef5390
```

### 2. DB Fetch

```console
$ vuls db fetch
```

### 3. init config & configuration change

Execute the following command to output a config template to stdout.
Make a file of it and change the necessary host part, path to the DB, etc. to suit your environment.

```console
$ vuls config init
```

### Optional. add to list of known hosts

When using remote as the host type, make an ssh connection to the remote host.
Before scanning, register the host in the known_hosts.

```console
$ ssh -i /home/mainek00n/.ssh/id_rsa -p 2222 root@127.0.0.1
The authenticity of host '[127.0.0.1]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is SHA256:dK+aO73n6hymIC3+3yFFHpvyNu/txTYi/LXvMl/TzOk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[127.0.0.1]:2222' (ED25519) to the list of known hosts.
```

### 4. Scan

```console
$ vuls scan
Scan Summary
============
local (ubuntu 22.04): success ospkg: 2663, cpe: 0 installed
remote (debian 11): success ospkg: 319, cpe: 0 installed
cpe: success ospkg: 0, cpe: 1 installed

or 

$ vuls server

$ cat machine.json
{
    "contents": [
        {
            "content_type": "os-release",
            "content": "PRETTY_NAME=\"Ubuntu 22.04.1 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nVERSION=\"22.04.1 LTS (Jammy Jellyfish)\"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nHOME_URL=\"https:\/\/www.ubuntu.com\/\"\nSUPPORT_URL=\"https:\/\/help.ubuntu.com\/\"\nBUG_REPORT_URL=\"https:\/\/bugs.launchpad.net\/ubuntu\/\"\nPRIVACY_POLICY_URL=\"https:\/\/www.ubuntu.com\/legal\/terms-and-policies\/privacy-policy\"\nUBUNTU_CODENAME=jammy"
        },
        {
            "content_type": "dpkg",
            "content": "accountsservice,ii ,22.07.5-2ubuntu1.3,amd64,accountsservice,22.07.5-2ubuntu1.3\nacl,ii ,2.3.1-1,amd64,acl,2.3.1-1\nnvim-common,ii ,2:8.2.3995-1ubuntu2.1,all,vim,2:8.2.3995-1ubuntu2.1\n"
        }
    ]
}

$ curl -s -X POST -H "Content-Type: application/json" -d @machine.json  127.0.0.1:5515/scan | jq
{
  "name": "8002e134-dc2d-4786-96b3-e751103fe5c3",
  "family": "ubuntu",
  "release": "22.04",
  "scanned_at": "2022-11-14T10:41:07.558379311+09:00",
  "packages": {
    "kernel": {},
    "os_pkg": {
      "accountsservice": {
        "name": "accountsservice",
        "version": "22.07.5-2ubuntu1.3",
        "arch": "amd64",
        "src_name": "accountsservice",
        "src_version": "22.07.5-2ubuntu1.3"
      },
      "acl": {
        "name": "acl",
        "version": "2.3.1-1",
        "arch": "amd64",
        "src_name": "acl",
        "src_version": "2.3.1-1"
      },
      "nvim-common": {
        "name": "nvim-common",
        "version": "2:8.2.3995-1ubuntu2.1",
        "arch": "all",
        "src_name": "vim",
        "src_version": "2:8.2.3995-1ubuntu2.1"
      }
    }
  },
  "config": {}
}
```

### 5. Detect

```console
$ vuls detect
Detect Summary
==============
local (ubuntu 22.04) : success 143 CVEs detected
remote (debian 11) : success 101 CVEs detected
cpe : success 7 CVEs detected

or 

$ vuls server

$ cat scan.json
{
  "name": "8002e134-dc2d-4786-96b3-e751103fe5c3",
  "family": "ubuntu",
  "release": "22.04",
  "scanned_at": "2022-11-14T10:41:07.558379311+09:00",
  "packages": {
    "kernel": {},
    "os_pkg": {
      "accountsservice": {
        "name": "accountsservice",
        "version": "22.07.5-2ubuntu1.3",
        "arch": "amd64",
        "src_name": "accountsservice",
        "src_version": "22.07.5-2ubuntu1.3"
      },
      "acl": {
        "name": "acl",
        "version": "2.3.1-1",
        "arch": "amd64",
        "src_name": "acl",
        "src_version": "2.3.1-1"
      },
      "nvim-common": {
        "name": "nvim-common",
        "version": "2:8.2.3995-1ubuntu2.1",
        "arch": "all",
        "src_name": "vim",
        "src_version": "2:8.2.3995-1ubuntu2.1"
      }
    }
  },
  "config": {}
}

$ curl -s -X POST -H "Content-Type: application/json" -d @scan.json  127.0.0.1:5515/detect | jq
{
    "name": "0c33d5fc-add4-465b-9ffa-90e74036259d",
    "family": "ubuntu",
    "release": "22.04",
    "scanned_at": "2022-11-14T10:42:31.863598309+09:00",
    "detectedd_at": "2022-11-14T10:42:50.677085953+09:00",
    "packages": {
      "kernel": {},
      "os_pkg": {
        "accountsservice": {
          "name": "accountsservice",
          "version": "22.07.5-2ubuntu1.3",
          "arch": "amd64",
          "src_name": "accountsservice",
          "src_version": "22.07.5-2ubuntu1.3"
        },
        "acl": {
          "name": "acl",
          "version": "2.3.1-1",
          "arch": "amd64",
          "src_name": "acl",
          "src_version": "2.3.1-1"
        },
        "nvim-common": {
          "name": "nvim-common",
          "version": "2:8.2.3995-1ubuntu2.1",
          "arch": "all",
          "src_name": "vim",
          "src_version": "2:8.2.3995-1ubuntu2.1"
        }
      }
    },
    "scanned_cves": {
      "CVE-2022-0128": {
        "content": {
          "official": {
            "id": "CVE-2022-0128",
            "advisory": [
              "mitre",
              "nvd",
              "alpine:3.12:CVE-2022-0128",
              "alpine:3.13:CVE-2022-0128",
              "alpine:3.14:CVE-2022-0128",
              "alpine:3.15:CVE-2022-0128",
              "alpine:3.16:CVE-2022-0128",
              "amazon:2022:ALAS2022-2022-014",
              "debian_security_tracker:11:CVE-2022-0128",
              "debian_security_tracker:12:CVE-2022-0128",
              "debian_security_tracker:sid:CVE-2022-0128",
              "debian_security_tracker:10:CVE-2022-0128",
              "redhat_oval:6-including-unpatched:oval:com.redhat.unaffected:def:20220128",
              "redhat_oval:7-including-unpatched:oval:com.redhat.unaffected:def:20220128",
              "redhat_oval:8-including-unpatched:oval:com.redhat.unaffected:def:20220128",
              "redhat_oval:9-including-unpatched:oval:com.redhat.unaffected:def:20220128",
              "suse_oval:opensuse.leap.15.3:oval:org.opensuse.security:def:20220128",
              "suse_oval:opensuse.leap.15.4:oval:org.opensuse.security:def:20220128",
              "suse_oval:suse.linux.enterprise.desktop.15:oval:org.opensuse.security:def:20220128",
              "suse_oval:suse.linux.enterprise.server.12:oval:org.opensuse.security:def:20220128",
              "suse_oval:suse.linux.enterprise.server.15:oval:org.opensuse.security:def:20220128",
              "suse_cvrf",
              "ubuntu_oval:14.04:oval:com.ubuntu.trusty:def:202201280000000",
              "ubuntu_oval:16.04:oval:com.ubuntu.xenial:def:202201280000000",
              "ubuntu_oval:21.04:oval:com.ubuntu.hirsute:def:202201280000000",
              "ubuntu_oval:22.04:oval:com.ubuntu.jammy:def:202201280000000",
              "ubuntu_oval:22.10:oval:com.ubuntu.kinetic:def:202201280000000",
              "ubuntu_security_tracker"
            ],
            "title": "CVE-2022-0128",
            "description": "vim is vulnerable to Out-of-bounds Read",
            "cvss": [
              {
                "source": "nvd",
                "version": "2.0",
                "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "score": 6.8,
                "severity": "MEDIUM"
              },
              {
                "source": "nvd",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "score": 7.8,
                "severity": "HIGH"
              },
              {
                "source": "amazon:2022:ALAS2022-2022-014",
                "severity": "Important"
              },
              {
                "source": "redhat_oval:7-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
                "score": 6.1,
                "severity": "moderate"
              },
              {
                "source": "redhat_oval:8-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
                "score": 6.1,
                "severity": "moderate"
              },
              {
                "source": "redhat_oval:9-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
                "score": 6.1,
                "severity": "moderate"
              },
              {
                "source": "redhat_oval:6-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
                "score": 6.1,
                "severity": "moderate"
              },
              {
                "source": "suse_oval:opensuse.leap.15.4:oval:org.opensuse.security:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3,
                "severity": "low"
              },
              {
                "source": "suse_oval:suse.linux.enterprise.desktop.15:oval:org.opensuse.security:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3,
                "severity": "low"
              },
              {
                "source": "suse_oval:suse.linux.enterprise.server.12:oval:org.opensuse.security:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3,
                "severity": "low"
              },
              {
                "source": "suse_oval:suse.linux.enterprise.server.15:oval:org.opensuse.security:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3,
                "severity": "low"
              },
              {
                "source": "suse_oval:opensuse.leap.15.3:oval:org.opensuse.security:def:20220128",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3,
                "severity": "low"
              },
              {
                "source": "suse_cvrf",
                "version": "2.0",
                "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P",
                "score": 6.8
              },
              {
                "source": "suse_cvrf",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                "score": 3.3
              },
              {
                "source": "ubuntu_oval:14.04:oval:com.ubuntu.trusty:def:202201280000000",
                "severity": "Medium"
              },
              {
                "source": "ubuntu_oval:16.04:oval:com.ubuntu.xenial:def:202201280000000",
                "severity": "Medium"
              },
              {
                "source": "ubuntu_oval:21.04:oval:com.ubuntu.hirsute:def:202201280000000",
                "severity": "Medium"
              },
              {
                "source": "ubuntu_oval:22.04:oval:com.ubuntu.jammy:def:202201280000000",
                "severity": "Medium"
              },
              {
                "source": "ubuntu_oval:22.10:oval:com.ubuntu.kinetic:def:202201280000000",
                "severity": "Medium"
              },
              {
                "source": "ubuntu_security_tracker",
                "severity": "medium"
              },
              {
                "source": "ubuntu_security_tracker",
                "version": "3.1",
                "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "score": 7.8,
                "severity": "HIGH"
              }
            ],
            "epss": {
              "epss": 0.01537,
              "percentile": 0.73989
            },
            "cwe": [
              {
                "source": [
                  "nvd",
                  "redhat_oval:6-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                  "redhat_oval:7-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                  "redhat_oval:8-including-unpatched:oval:com.redhat.unaffected:def:20220128",
                  "redhat_oval:9-including-unpatched:oval:com.redhat.unaffected:def:20220128"
                ],
                "id": "125"
              }
            ],
            "exploit": [
              {
                "source": [
                  "nvd",
                  "inthewild",
                  "trickest"
                ],
                "url": "https://huntr.dev/bounties/63f51299-008a-4112-b85b-1e904aadd4ba"
              }
            ],
            "published": "2022-01-06T17:15:00Z",
            "modified": "2022-11-02T13:18:00Z",
            "reference": [
              "http://www.openwall.com/lists/oss-security/2022/01/15/1",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4166",
              "https://access.redhat.com/security/cve/CVE-2022-0128",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011493.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011575.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011592.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-June/011301.html",
              "https://bugs.launchpad.net/ubuntu/+bug/https://huntr.dev/bounties/63f51299-008a-4112-b85b-1e904aadd4ba",
              "https://support.apple.com/kb/HT213343",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4019",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4187",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4193",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0156",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-August/011821.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-September/012143.html",
              "https://bugzilla.suse.com/1194388",
              "https://www.suse.com/support/security/rating/",
              "http://people.canonical.com/~ubuntu-security/cve/2022/CVE-2022-0128.html",
              "http://seclists.org/fulldisclosure/2022/May/35",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4069",
              "https://www.suse.com/security/cve/CVE-2022-0128",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011573.html",
              "http://seclists.org/fulldisclosure/2022/Mar/29",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0128",
              "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0128",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-August/011795.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011495.html",
              "https://ubuntu.com/security/CVE-2022-0128",
              "https://huntr.dev/bounties/63f51299-008a-4112-b85b-1e904aadd4ba",
              "http://seclists.org/fulldisclosure/2022/Jul/14",
              "https://security.gentoo.org/glsa/202208-32",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0158",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011591.html",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4136",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4173",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011494.html",
              "https://support.apple.com/kb/HT213183",
              "https://support.apple.com/kb/HT213256",
              "https://github.com/vim/vim/commit/d3a117814d6acbf0dca3eff1a7626843b9b3734a",
              "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-4192",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011574.html",
              "https://lists.suse.com/pipermail/sle-security-updates/2022-July/011593.html"
            ]
          }
        },
        "affected_packages": [
          {
            "name": "vim",
            "source": "official:ubuntu_security_tracker:CVE-2022-0128",
            "status": "needed"
          }
        ]
      },
      ...
    },
    "config": {
      "detect": {
        "path": "/home/mainek00n/github/github.com/future-architect/vuls/vuls.db",
        "result_dir": ""
      }
    }
  }
```

### 6. Report

```console
$ vuls report --format list
cpe
===
+----------------+----------------------------+------+----------+-------+----------------------------------------+--------+----------+
|     CVEID      |           VECTOR           | CVSS |   EPSS   |  KEV  |                PACKAGE                 | STATUS |  SOURCE  |
+----------------+----------------------------+------+----------+-------+----------------------------------------+--------+----------+
| CVE-2021-44228 | AV:N/AC:M/Au:N/C:C/I:C/A:C |  9.3 | 0.911590 | true  | cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:* |        | official |
+----------------+----------------------------+------+----------+-------+                                        +--------+          +
| CVE-2022-23307 | AV:N/AC:L/Au:S/C:C/I:C/A:C |  9.0 | 0.011640 | false |                                        |        |          |
+----------------+----------------------------+------+----------+       +                                        +--------+          +
| CVE-2021-44832 | AV:N/AC:M/Au:S/C:C/I:C/A:C |  8.5 | 0.686370 |       |                                        |        |          |
+----------------+----------------------------+------+----------+       +                                        +--------+          +
| CVE-2022-23305 | AV:N/AC:M/Au:N/C:P/I:P/A:P |  6.8 | 0.017420 |       |                                        |        |          |
+----------------+----------------------------+------+----------+       +                                        +--------+          +
| CVE-2022-23302 | AV:N/AC:M/Au:S/C:P/I:P/A:P |  6.0 | 0.091480 |       |                                        |        |          |
+----------------+----------------------------+------+----------+       +                                        +--------+          +
| CVE-2021-45046 | AV:N/AC:H/Au:N/C:P/I:P/A:P |  5.1 | 0.719510 |       |                                        |        |          |
+----------------+----------------------------+------+----------+       +                                        +--------+          +
| CVE-2021-45105 | AV:N/AC:M/Au:N/C:N/I:N/A:P |  4.3 | 0.442620 |       |                                        |        |          |
+----------------+----------------------------+------+----------+-------+----------------------------------------+--------+----------+

local (ubuntu 22.04)
====================
+----------------+----------------------------+------+----------+-------+-----------------------+----------+----------+
|     CVEID      |           VECTOR           | CVSS |   EPSS   |  KEV  |        PACKAGE        |  STATUS  |  SOURCE  |
+----------------+----------------------------+------+----------+-------+-----------------------+----------+----------+
| CVE-2022-0318  | AV:N/AC:L/Au:N/C:P/I:P/A:P |  7.5 | 0.011830 | false | vim                   | needed   | official |
+----------------+----------------------------+------+----------+       +-----------------------+          +          +
| CVE-2022-25255 | AV:L/AC:L/Au:N/C:C/I:C/A:C |  7.2 | 0.009500 |       | qtbase-opensource-src |          |          |
+----------------+                            +      +----------+       +-----------------------+          +          +
| CVE-2022-0995  |                            |      | 0.024480 |       | linux                 |          |          |
+----------------+----------------------------+------+----------+       +-----------------------+          +          +
...
+----------------+----------------------------+------+----------+       +-----------------------+----------+          +
| CVE-2022-42799 |                            |      | 0.011080 |       | webkit2gtk            | needed   |          |
+----------------+----------------------------+------+----------+       +-----------------------+          +          +
| CVE-2022-3061  |                            |      | 0.008900 |       | linux                 |          |          |
+----------------+----------------------------+------+----------+-------+-----------------------+----------+----------+

remote (debian 11)
==================
+----------------+----------------------------+------+----------+-------+------------+--------+----------+
|     CVEID      |           VECTOR           | CVSS |   EPSS   |  KEV  |  PACKAGE   | STATUS |  SOURCE  |
+----------------+----------------------------+------+----------+-------+------------+--------+----------+
| CVE-2022-31782 | AV:N/AC:M/Au:N/C:P/I:P/A:P |  6.8 | 0.008850 | false | freetype   | open   | official |
+----------------+                            +      +----------+       +------------+        +          +
| CVE-2022-1304  |                            |      | 0.010360 |       | e2fsprogs  |        |          |
+----------------+----------------------------+------+----------+       +------------+        +          +
| CVE-2022-1587  | AV:N/AC:L/Au:N/C:P/I:N/A:P |  6.4 | 0.011080 |       | pcre2      |        |          |
+----------------+                            +      +----------+       +            +        +          +
| CVE-2022-1586  |                            |      | 0.011830 |       |            |        |          |
+----------------+----------------------------+------+          +       +------------+        +          +
| CVE-2022-2097  | AV:N/AC:L/Au:N/C:P/I:N/A:N |  5.0 |          |       | openssl    |        |          |
+----------------+----------------------------+------+----------+       +------------+        +          +
...
+----------------+----------------------------+------+----------+       +------------+        +          +
| CVE-2022-38126 |                            |      | 0.008850 |       | binutils   |        |          |
+----------------+----------------------------+------+          +       +------------+        +          +
| CVE-2022-41848 |                            |      |          |       | linux      |        |          |
+----------------+----------------------------+------+----------+-------+------------+--------+----------+


```