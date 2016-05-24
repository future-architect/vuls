# Change Log

## [v0.1.4](https://github.com/future-architect/vuls/tree/v0.1.4) (2016-05-24)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.3...v0.1.4)

**Implemented enhancements:**

- Initial fetch from NVD is too heavy \(2.3 GB of memory consumed\) [\#27](https://github.com/future-architect/vuls/issues/27)
- Enable to show previous scan result [\#69](https://github.com/future-architect/vuls/pull/69) ([kotakanbe](https://github.com/kotakanbe))
- Add ignore-unscored-cves option [\#68](https://github.com/future-architect/vuls/pull/68) ([kotakanbe](https://github.com/kotakanbe))
- Support dynamic scanning docker container [\#67](https://github.com/future-architect/vuls/pull/67) ([kotakanbe](https://github.com/kotakanbe))
- Add version flag [\#65](https://github.com/future-architect/vuls/pull/65) ([kotakanbe](https://github.com/kotakanbe))
- Update Dockerfile [\#57](https://github.com/future-architect/vuls/pull/57) ([theonlydoo](https://github.com/theonlydoo))
- Update run.sh [\#56](https://github.com/future-architect/vuls/pull/56) ([theonlydoo](https://github.com/theonlydoo))
- Support Windows [\#33](https://github.com/future-architect/vuls/pull/33) ([mattn](https://github.com/mattn))

**Fixed bugs:**

- vuls scan -cvss-over does not work. [\#59](https://github.com/future-architect/vuls/issues/59)
- `panic: runtime error: invalid memory address or nil pointer dereference` when scan CentOS5.5 [\#58](https://github.com/future-architect/vuls/issues/58)
-  It rans out of memory. [\#47](https://github.com/future-architect/vuls/issues/47)
- BUG: vuls scan on CentOS with Japanese environment. [\#43](https://github.com/future-architect/vuls/issues/43)
- yum --color=never [\#36](https://github.com/future-architect/vuls/issues/36)
- Failed to parse yum check-update [\#32](https://github.com/future-architect/vuls/issues/32)
- Pointless sudo [\#29](https://github.com/future-architect/vuls/issues/29)
- Can't init database in a path having blanks [\#26](https://github.com/future-architect/vuls/issues/26)
- Fix pointless sudo in debian.go \#29 [\#66](https://github.com/future-architect/vuls/pull/66) ([kotakanbe](https://github.com/kotakanbe))
- Fix error handling of httpGet in cve-client \#58 [\#64](https://github.com/future-architect/vuls/pull/64) ([kotakanbe](https://github.com/kotakanbe))
- Fix nil pointer at error handling of cve\_client \#58 [\#63](https://github.com/future-architect/vuls/pull/63) ([kotakanbe](https://github.com/kotakanbe))
- Set language en\_US. [\#61](https://github.com/future-architect/vuls/pull/61) ([pabroff](https://github.com/pabroff))
- Fix -cvss-over flag \#59 [\#60](https://github.com/future-architect/vuls/pull/60) ([kotakanbe](https://github.com/kotakanbe))
- Fix scan on Japanese environment. [\#55](https://github.com/future-architect/vuls/pull/55) ([pabroff](https://github.com/pabroff))
- Fix a typo: replace Depricated by Deprecated. [\#54](https://github.com/future-architect/vuls/pull/54) ([jody-frankowski](https://github.com/jody-frankowski))
- Fix yes no infinite loop while doing yum update --changelog on root@CentOS \#47 [\#50](https://github.com/future-architect/vuls/pull/50) ([pabroff](https://github.com/pabroff))
- Fix $servername in output of discover command [\#45](https://github.com/future-architect/vuls/pull/45) ([kotakanbe](https://github.com/kotakanbe))

## [v0.1.3](https://github.com/future-architect/vuls/tree/v0.1.3) (2016-04-21)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.2...v0.1.3)

**Implemented enhancements:**

- Add sudo support for prepare [\#11](https://github.com/future-architect/vuls/issues/11)
- Dockerfile? [\#10](https://github.com/future-architect/vuls/issues/10)
- Update README [\#41](https://github.com/future-architect/vuls/pull/41) ([theonlydoo](https://github.com/theonlydoo))
- Sparse dockerization [\#38](https://github.com/future-architect/vuls/pull/38) ([theonlydoo](https://github.com/theonlydoo))
- No password in config [\#35](https://github.com/future-architect/vuls/pull/35) ([kotakanbe](https://github.com/kotakanbe))
- Fr readme translation [\#23](https://github.com/future-architect/vuls/pull/23) ([novakin](https://github.com/novakin))

**Fixed bugs:**

- Issues updating CVE database behind https proxy [\#39](https://github.com/future-architect/vuls/issues/39)
- Vuls failed to parse yum check-update [\#24](https://github.com/future-architect/vuls/issues/24)
- Fix yum to yum --color=never \#36 [\#42](https://github.com/future-architect/vuls/pull/42) ([kotakanbe](https://github.com/kotakanbe))
- Fix parse yum check update [\#40](https://github.com/future-architect/vuls/pull/40) ([kotakanbe](https://github.com/kotakanbe))
- fix typo [\#31](https://github.com/future-architect/vuls/pull/31) ([blue119](https://github.com/blue119))
- Fix error while parsing yum check-update \#24 [\#30](https://github.com/future-architect/vuls/pull/30) ([kotakanbe](https://github.com/kotakanbe))

**Closed issues:**

- Unable to scan on ubuntu because changelog.ubuntu.com is down... [\#21](https://github.com/future-architect/vuls/issues/21)
- err: Not initialize\(d\) yet.. [\#16](https://github.com/future-architect/vuls/issues/16)
- Errors when using fish shell [\#8](https://github.com/future-architect/vuls/issues/8)

## [v0.1.2](https://github.com/future-architect/vuls/tree/v0.1.2) (2016-04-12)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.1...v0.1.2)

**Fixed bugs:**

- Maximum 6 nodes available to scan [\#12](https://github.com/future-architect/vuls/issues/12)
- panic: runtime error: index out of range [\#5](https://github.com/future-architect/vuls/issues/5)
- Fix sudo option on RedHat like Linux and change some messages. [\#20](https://github.com/future-architect/vuls/pull/20) ([kotakanbe](https://github.com/kotakanbe))
- Typo fix and updated readme [\#19](https://github.com/future-architect/vuls/pull/19) ([Euan-Kerr](https://github.com/Euan-Kerr))
- remove a period at the end of error messages. [\#18](https://github.com/future-architect/vuls/pull/18) ([kotakanbe](https://github.com/kotakanbe))
- fix error while yum updateinfo --security update on rhel@aws [\#17](https://github.com/future-architect/vuls/pull/17) ([kotakanbe](https://github.com/kotakanbe))
- Fixed typos [\#15](https://github.com/future-architect/vuls/pull/15) ([radarhere](https://github.com/radarhere))
- Typo fix in error messages [\#14](https://github.com/future-architect/vuls/pull/14) ([Bregor](https://github.com/Bregor))
- Fix index out of range error when the number of servers is over 6. \#12 [\#13](https://github.com/future-architect/vuls/pull/13) ([kotakanbe](https://github.com/kotakanbe))
- Revise small grammar mistakes in serverapi.go [\#9](https://github.com/future-architect/vuls/pull/9) ([cpobrien](https://github.com/cpobrien))
- Fix error handling in HTTP backoff function [\#7](https://github.com/future-architect/vuls/pull/7) ([kotakanbe](https://github.com/kotakanbe))

## [v0.1.1](https://github.com/future-architect/vuls/tree/v0.1.1) (2016-04-06)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.0...v0.1.1)

**Fixed bugs:**

- Typo in Exapmle [\#6](https://github.com/future-architect/vuls/pull/6) ([toli](https://github.com/toli))

## [v0.1.0](https://github.com/future-architect/vuls/tree/v0.1.0) (2016-04-04)
**Merged pull requests:**

- English translation [\#4](https://github.com/future-architect/vuls/pull/4) ([hikachan](https://github.com/hikachan))
- English translation [\#3](https://github.com/future-architect/vuls/pull/3) ([chewyinping](https://github.com/chewyinping))
- Add a Bitdeli Badge to README [\#2](https://github.com/future-architect/vuls/pull/2) ([bitdeli-chef](https://github.com/bitdeli-chef))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*