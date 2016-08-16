# Change Log

## [v0.1.5](https://github.com/future-architect/vuls/tree/v0.1.5) (2016-08-16)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.4...v0.1.5)

**Implemented enhancements:**

- Enable to scan without running go-cve-dictionary as server mode [\#84](https://github.com/future-architect/vuls/issues/84)
- Support high-speed scanning for CentOS [\#138](https://github.com/future-architect/vuls/pull/138) ([tai-ga](https://github.com/tai-ga))
- Add configtest subcommand. skip un-ssh-able servers. [\#134](https://github.com/future-architect/vuls/pull/134) ([kotakanbe](https://github.com/kotakanbe))
- Support -report-azure-blob option [\#130](https://github.com/future-architect/vuls/pull/130) ([kotakanbe](https://github.com/kotakanbe))
- Add optional key-values that will be outputted to JSON in config [\#117](https://github.com/future-architect/vuls/pull/117) ([kotakanbe](https://github.com/kotakanbe))
- Change dir structure [\#115](https://github.com/future-architect/vuls/pull/115) ([kotakanbe](https://github.com/kotakanbe))
- Add some validation of loading config. user, host and port [\#113](https://github.com/future-architect/vuls/pull/113) ([kotakanbe](https://github.com/kotakanbe))
- Support scanning with external ssh command [\#101](https://github.com/future-architect/vuls/pull/101) ([kotakanbe](https://github.com/kotakanbe))
- Detect Platform and get instance-id of amazon ec2 [\#95](https://github.com/future-architect/vuls/pull/95) ([kotakanbe](https://github.com/kotakanbe))
- Add -report-s3 option [\#92](https://github.com/future-architect/vuls/pull/92) ([kotakanbe](https://github.com/kotakanbe))
- Added FreeBSD support. [\#90](https://github.com/future-architect/vuls/pull/90) ([justyntemme](https://github.com/justyntemme))
- Add glide files for vendoring [\#89](https://github.com/future-architect/vuls/pull/89) ([kotakanbe](https://github.com/kotakanbe))
- Fix README, change -cvedbpath to -cve-dictionary-dbpath \#84 [\#85](https://github.com/future-architect/vuls/pull/85) ([kotakanbe](https://github.com/kotakanbe))
- Add option for it get cve detail from cve.sqlite3. [\#81](https://github.com/future-architect/vuls/pull/81) ([ymd38](https://github.com/ymd38))
- Add -report-text option, Fix small bug of report in japanese [\#78](https://github.com/future-architect/vuls/pull/78) ([kotakanbe](https://github.com/kotakanbe))
- Add JSONWriter, Fix CVE sort order of report [\#77](https://github.com/future-architect/vuls/pull/77) ([kotakanbe](https://github.com/kotakanbe))

**Fixed bugs:**

- Docker: Panic [\#76](https://github.com/future-architect/vuls/issues/76)
- Fix apt command to scan correctly when system locale is not english [\#149](https://github.com/future-architect/vuls/pull/149) ([kit494way](https://github.com/kit494way))
- Disable -ask-sudo-password for security reasons [\#148](https://github.com/future-architect/vuls/pull/148) ([kotakanbe](https://github.com/kotakanbe))
- Fix no tty error while executing with -external-ssh option [\#143](https://github.com/future-architect/vuls/pull/143) ([kotakanbe](https://github.com/kotakanbe))
- wrong log packages [\#141](https://github.com/future-architect/vuls/pull/141) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Fix platform detection. [\#137](https://github.com/future-architect/vuls/pull/137) ([Rompei](https://github.com/Rompei))
- Fix nil pointer when scan with -cve-dictionary-dbpath and cpeNames [\#111](https://github.com/future-architect/vuls/pull/111) ([kotakanbe](https://github.com/kotakanbe))
- Remove vulndb file before pkg audit [\#110](https://github.com/future-architect/vuls/pull/110) ([kotakanbe](https://github.com/kotakanbe))
- Add error handling when unable to connect via ssh. status code: 255 [\#108](https://github.com/future-architect/vuls/pull/108) ([kotakanbe](https://github.com/kotakanbe))
- Enable to detect vulnerabilities on FreeBSD [\#98](https://github.com/future-architect/vuls/pull/98) ([kotakanbe](https://github.com/kotakanbe))
- Fix unknown format err while check-update on RHEL6.5 [\#93](https://github.com/future-architect/vuls/pull/93) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Fix type of SMTP Port of discovery command's output [\#88](https://github.com/future-architect/vuls/pull/88) ([kotakanbe](https://github.com/kotakanbe))
- Fix error msg when go-cve-dictionary is unavailable \#84 [\#86](https://github.com/future-architect/vuls/pull/86) ([kotakanbe](https://github.com/kotakanbe))
- Fix error handling to avoid nil pointer err on debian [\#83](https://github.com/future-architect/vuls/pull/83) ([kotakanbe](https://github.com/kotakanbe))
- Fix nil pointer while doing apt-cache policy on ubuntu \#76 [\#82](https://github.com/future-architect/vuls/pull/82) ([kotakanbe](https://github.com/kotakanbe))
- fix log import url [\#79](https://github.com/future-architect/vuls/pull/79) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Fix error handling of gorequest [\#75](https://github.com/future-architect/vuls/pull/75) ([kotakanbe](https://github.com/kotakanbe))
- Fix freezing forever when no args specified in TUI mode [\#73](https://github.com/future-architect/vuls/pull/73) ([kotakanbe](https://github.com/kotakanbe))
- mv version.go version/version.go to run main.go without compile [\#71](https://github.com/future-architect/vuls/pull/71) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))

**Closed issues:**

- SSh password authentication failed on FreeBSD [\#99](https://github.com/future-architect/vuls/issues/99)
- BUG: -o pipefail is not work on FreeBSD's /bin/sh. because it isn't bash [\#91](https://github.com/future-architect/vuls/issues/91)
- Use ~/.ssh/config [\#62](https://github.com/future-architect/vuls/issues/62)
- SSH ciphers [\#37](https://github.com/future-architect/vuls/issues/37)

**Merged pull requests:**

- Update README \#138 [\#144](https://github.com/future-architect/vuls/pull/144) ([kotakanbe](https://github.com/kotakanbe))
- Fix a typo [\#142](https://github.com/future-architect/vuls/pull/142) ([dtan4](https://github.com/dtan4))
- Remove unnecessary step in readme of docker setup [\#140](https://github.com/future-architect/vuls/pull/140) ([mikkame](https://github.com/mikkame))
- Update logo [\#139](https://github.com/future-architect/vuls/pull/139) ([chanomaru](https://github.com/chanomaru))
- Update README.ja.md to fix wrong tips. [\#135](https://github.com/future-architect/vuls/pull/135) ([a2atsu](https://github.com/a2atsu))
- add tips about NVD JVN issue [\#133](https://github.com/future-architect/vuls/pull/133) ([a2atsu](https://github.com/a2atsu))
- Fix README wrong links [\#129](https://github.com/future-architect/vuls/pull/129) ([aomoriringo](https://github.com/aomoriringo))
- Add logo [\#126](https://github.com/future-architect/vuls/pull/126) ([chanomaru](https://github.com/chanomaru))
- Improve setup/docker [\#125](https://github.com/future-architect/vuls/pull/125) ([kotakanbe](https://github.com/kotakanbe))
- Fix scan command help [\#124](https://github.com/future-architect/vuls/pull/124) ([aomoriringo](https://github.com/aomoriringo))
- added dockernized-vuls with vulsrepo [\#121](https://github.com/future-architect/vuls/pull/121) ([hikachan](https://github.com/hikachan))
- Fix detect platform on azure and degital ocean [\#119](https://github.com/future-architect/vuls/pull/119) ([kotakanbe](https://github.com/kotakanbe))
- Remove json marshall-indent [\#118](https://github.com/future-architect/vuls/pull/118) ([kotakanbe](https://github.com/kotakanbe))
- Improve Readme.ja [\#116](https://github.com/future-architect/vuls/pull/116) ([kotakanbe](https://github.com/kotakanbe))
- Add architecture diag to README.md [\#114](https://github.com/future-architect/vuls/pull/114) ([kotakanbe](https://github.com/kotakanbe))
- Rename linux.go to base.go [\#100](https://github.com/future-architect/vuls/pull/100) ([kotakanbe](https://github.com/kotakanbe))
- Update README.md [\#74](https://github.com/future-architect/vuls/pull/74) ([yoshi-taka](https://github.com/yoshi-taka))
- Refactoring debian.go [\#72](https://github.com/future-architect/vuls/pull/72) ([kotakanbe](https://github.com/kotakanbe))

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