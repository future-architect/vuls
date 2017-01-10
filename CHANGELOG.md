# Change Log

## [v0.2.0](https://github.com/future-architect/vuls/tree/v0.2.0) (2017-01-10)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.7...v0.2.0)

**Fixed bugs:**

- Failed to scan on RHEL5 [\#94](https://github.com/future-architect/vuls/issues/94)

**Closed issues:**

- vuls prepare failed to centos7 [\#275](https://github.com/future-architect/vuls/issues/275)
- gocui.NewGui now takes a parameter [\#261](https://github.com/future-architect/vuls/issues/261)
- Add a `--yes` flag to bypass interactive prompt for `vuls prepare` [\#260](https://github.com/future-architect/vuls/issues/260)
- `vuls prepare` doesn't work on Debian host due to apt-get confirmation prompt [\#251](https://github.com/future-architect/vuls/issues/251)

**Merged pull requests:**

- Fix container os detection [\#287](https://github.com/future-architect/vuls/pull/287) ([jiazio](https://github.com/jiazio))
- Add date header to report mail. [\#283](https://github.com/future-architect/vuls/pull/283) ([ymomoi](https://github.com/ymomoi))
- Add Content-Type header to report/mail.go . [\#280](https://github.com/future-architect/vuls/pull/280) ([hogehogehugahuga](https://github.com/hogehogehugahuga))
- Keep output of "vuls scan -report-\*" to be same every times [\#272](https://github.com/future-architect/vuls/pull/272) ([yoheimuta](https://github.com/yoheimuta))
- Fix JSON-dir regex pattern \#265 [\#271](https://github.com/future-architect/vuls/pull/271) ([kotakanbe](https://github.com/kotakanbe))
- Add report subcommand, change scan options. \#239 [\#270](https://github.com/future-architect/vuls/pull/270) ([kotakanbe](https://github.com/kotakanbe))
- Add --assume-yes to prepare \#260 [\#266](https://github.com/future-architect/vuls/pull/266) ([Code0x58](https://github.com/Code0x58))
- Use RFC3339 timestamps in the results [\#265](https://github.com/future-architect/vuls/pull/265) ([Code0x58](https://github.com/Code0x58))
- Stop quietly ignoring `--ssh-external` on Windows [\#263](https://github.com/future-architect/vuls/pull/263) ([Code0x58](https://github.com/Code0x58))
- Fix gocui.NewGui after signature change \#261 [\#262](https://github.com/future-architect/vuls/pull/262) ([Code0x58](https://github.com/Code0x58))
- Replace inconsistent tabs with spaces [\#254](https://github.com/future-architect/vuls/pull/254) ([Code0x58](https://github.com/Code0x58))
- Fix non-interactive `apt-get install` \#251 [\#253](https://github.com/future-architect/vuls/pull/253) ([Code0x58](https://github.com/Code0x58))
- Fix README [\#249](https://github.com/future-architect/vuls/pull/249) ([usiusi360](https://github.com/usiusi360))

## [v0.1.7](https://github.com/future-architect/vuls/tree/v0.1.7) (2016-11-08)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.6...v0.1.7)

**Implemented enhancements:**

- Enable to scan only docker container, without docker host [\#122](https://github.com/future-architect/vuls/issues/122)
- Add -skip-broken option \[CentOS only\] \#245 [\#248](https://github.com/future-architect/vuls/pull/248) ([kotakanbe](https://github.com/kotakanbe))
- Display unknown CVEs to TUI [\#244](https://github.com/future-architect/vuls/pull/244) ([kotakanbe](https://github.com/kotakanbe))
- Add the XML output [\#240](https://github.com/future-architect/vuls/pull/240) ([gleentea](https://github.com/gleentea))
- add '-ssh-external' option to prepare subcommand [\#234](https://github.com/future-architect/vuls/pull/234) ([mykstmhr](https://github.com/mykstmhr))
- Integrate OWASP Dependency Check [\#232](https://github.com/future-architect/vuls/pull/232) ([kotakanbe](https://github.com/kotakanbe))
- Add support for reading CVE data from MySQL. [\#225](https://github.com/future-architect/vuls/pull/225) ([oswell](https://github.com/oswell))
- Remove base docker image, -v shows commit hash [\#223](https://github.com/future-architect/vuls/pull/223) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Support ignore CveIDs in config [\#222](https://github.com/future-architect/vuls/pull/222) ([kotakanbe](https://github.com/kotakanbe))
- Confirm before installing dependencies on prepare [\#219](https://github.com/future-architect/vuls/pull/219) ([kotakanbe](https://github.com/kotakanbe))
- Remove all.json [\#218](https://github.com/future-architect/vuls/pull/218) ([kotakanbe](https://github.com/kotakanbe))
- Add GitHub issue template [\#217](https://github.com/future-architect/vuls/pull/217) ([kotakanbe](https://github.com/kotakanbe))
- Improve makefile, -version shows git hash, fix README [\#216](https://github.com/future-architect/vuls/pull/216) ([kotakanbe](https://github.com/kotakanbe))
- change e-mail package from gomail to net/smtp [\#211](https://github.com/future-architect/vuls/pull/211) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Add only-containers option to scan subcommand \#122 [\#190](https://github.com/future-architect/vuls/pull/190) ([kotakanbe](https://github.com/kotakanbe))
- Fix -results-dir option of scan subcommand [\#185](https://github.com/future-architect/vuls/pull/185) ([kotakanbe](https://github.com/kotakanbe))
- Show error when no scannable servers are detected. [\#177](https://github.com/future-architect/vuls/pull/177) ([kotakanbe](https://github.com/kotakanbe))
- Add sudo check to prepare subcommand [\#176](https://github.com/future-architect/vuls/pull/176) ([kotakanbe](https://github.com/kotakanbe))
- Supports yum --enablerepo option \(supports only base,updates for now\) [\#147](https://github.com/future-architect/vuls/pull/147) ([kotakanbe](https://github.com/kotakanbe))

**Fixed bugs:**

- Debian 8.6 \(jessie\) scan does not show vulnerable packages [\#235](https://github.com/future-architect/vuls/issues/235)
- panic: runtime error: index out of range - ubuntu 16.04 + vuls history [\#180](https://github.com/future-architect/vuls/issues/180)
- Moved golang.org/x/net/context to context [\#243](https://github.com/future-architect/vuls/pull/243) ([yoheimuta](https://github.com/yoheimuta))
- Fix changelog cache bug on Ubuntu and Debian \#235 [\#238](https://github.com/future-architect/vuls/pull/238) ([kotakanbe](https://github.com/kotakanbe))
- add '-ssh-external' option to prepare subcommand [\#234](https://github.com/future-architect/vuls/pull/234) ([mykstmhr](https://github.com/mykstmhr))
- Fixed error for the latest version of gocui [\#231](https://github.com/future-architect/vuls/pull/231) ([ymd38](https://github.com/ymd38))
- Handle the refactored gocui SetCurrentView method. [\#229](https://github.com/future-architect/vuls/pull/229) ([oswell](https://github.com/oswell))
- Fix locale env var LANG to LANGUAGE [\#215](https://github.com/future-architect/vuls/pull/215) ([kotakanbe](https://github.com/kotakanbe))
- Fixed bug with parsing update line on CentOS/RHEL [\#206](https://github.com/future-architect/vuls/pull/206) ([andyone](https://github.com/andyone))
- Fix defer cache.DB.close [\#201](https://github.com/future-architect/vuls/pull/201) ([kotakanbe](https://github.com/kotakanbe))
- Fix a help message of -report-azure-blob option [\#195](https://github.com/future-architect/vuls/pull/195) ([kotakanbe](https://github.com/kotakanbe))
- Fix error handling in tui [\#193](https://github.com/future-architect/vuls/pull/193) ([kotakanbe](https://github.com/kotakanbe))
- Fix not working changelog cache on Container [\#189](https://github.com/future-architect/vuls/pull/189) ([kotakanbe](https://github.com/kotakanbe))
- Fix release version detection on FreeBSD [\#184](https://github.com/future-architect/vuls/pull/184) ([kotakanbe](https://github.com/kotakanbe))
- Fix defer cahce.DB.close\(\) [\#183](https://github.com/future-architect/vuls/pull/183) ([kotakanbe](https://github.com/kotakanbe))
- Fix a mode of files/dir \(report, log\) [\#182](https://github.com/future-architect/vuls/pull/182) ([kotakanbe](https://github.com/kotakanbe))
- Fix a error when no json dirs are found under results \#180 [\#181](https://github.com/future-architect/vuls/pull/181) ([kotakanbe](https://github.com/kotakanbe))
- ssh-external option of configtest is not working \#178 [\#179](https://github.com/future-architect/vuls/pull/179) ([kotakanbe](https://github.com/kotakanbe))

**Closed issues:**

- --enable-repos of yum option [\#246](https://github.com/future-architect/vuls/issues/246)
- --skip-broken at yum option [\#245](https://github.com/future-architect/vuls/issues/245)
- Recent changes to gobui cause build failures [\#228](https://github.com/future-architect/vuls/issues/228)
- https://hub.docker.com/r/vuls/go-cve-dictionary/ is empty [\#208](https://github.com/future-architect/vuls/issues/208)
- Not able to install gomail fails [\#202](https://github.com/future-architect/vuls/issues/202)
- No results file created - vuls tui failed [\#199](https://github.com/future-architect/vuls/issues/199)
- Wrong file permissions for results/\*.json in official Docker container [\#197](https://github.com/future-architect/vuls/issues/197)
- Failed: Unknown OS Type [\#196](https://github.com/future-architect/vuls/issues/196)
- Segmentation fault with configtest [\#192](https://github.com/future-architect/vuls/issues/192)
- Failed to scan. err: No server defined. Check the configuration [\#187](https://github.com/future-architect/vuls/issues/187)
- vuls configtest -ssh-external doesnt work [\#178](https://github.com/future-architect/vuls/issues/178)
- apt-get update: time out [\#175](https://github.com/future-architect/vuls/issues/175)
- scanning on Centos6, but vuls recognizes debian. [\#174](https://github.com/future-architect/vuls/issues/174)
- Fix READMEja  \#164  [\#173](https://github.com/future-architect/vuls/issues/173)

**Merged pull requests:**

- Update README \#225 [\#242](https://github.com/future-architect/vuls/pull/242) ([kotakanbe](https://github.com/kotakanbe))
- fix readme [\#241](https://github.com/future-architect/vuls/pull/241) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Fix README \#234 [\#237](https://github.com/future-architect/vuls/pull/237) ([kotakanbe](https://github.com/kotakanbe))
- Update glide files [\#236](https://github.com/future-architect/vuls/pull/236) ([kotakanbe](https://github.com/kotakanbe))
- fix README [\#226](https://github.com/future-architect/vuls/pull/226) ([usiusi360](https://github.com/usiusi360))
- fix some misspelling. [\#221](https://github.com/future-architect/vuls/pull/221) ([ymomoi](https://github.com/ymomoi))
- fix docker readme [\#214](https://github.com/future-architect/vuls/pull/214) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Fix ja document about typo [\#213](https://github.com/future-architect/vuls/pull/213) ([shokohara](https://github.com/shokohara))
- fix readme [\#212](https://github.com/future-architect/vuls/pull/212) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- fix README [\#207](https://github.com/future-architect/vuls/pull/207) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- fix typo [\#204](https://github.com/future-architect/vuls/pull/204) ([usiusi360](https://github.com/usiusi360))
- fix gitignore [\#191](https://github.com/future-architect/vuls/pull/191) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))
- Update glide.lock [\#188](https://github.com/future-architect/vuls/pull/188) ([kotakanbe](https://github.com/kotakanbe))
- Fix path in setup/docker/README [\#186](https://github.com/future-architect/vuls/pull/186) ([dladuke](https://github.com/dladuke))
- Vuls and vulsrepo are now separated [\#163](https://github.com/future-architect/vuls/pull/163) ([hikachan](https://github.com/hikachan))

## [v0.1.6](https://github.com/future-architect/vuls/tree/v0.1.6) (2016-09-12)
[Full Changelog](https://github.com/future-architect/vuls/compare/v0.1.5...v0.1.6)

**Implemented enhancements:**

- High speed scan on Ubuntu/Debian [\#172](https://github.com/future-architect/vuls/pull/172) ([kotakanbe](https://github.com/kotakanbe))
- Support CWE\(Common Weakness Enumeration\) [\#169](https://github.com/future-architect/vuls/pull/169) ([kotakanbe](https://github.com/kotakanbe))
- Enable to scan without sudo on amazon linux [\#167](https://github.com/future-architect/vuls/pull/167) ([kotakanbe](https://github.com/kotakanbe))
- Remove deprecated options -use-unattended-upgrades,-use-yum-plugin-security [\#161](https://github.com/future-architect/vuls/pull/161) ([kotakanbe](https://github.com/kotakanbe))
- delete sqlite3 [\#152](https://github.com/future-architect/vuls/pull/152) ([sadayuki-matsuno](https://github.com/sadayuki-matsuno))

**Fixed bugs:**

- Failed to setup vuls docker [\#170](https://github.com/future-architect/vuls/issues/170)
- yum check-update error occurred when no reboot after kernel updating [\#165](https://github.com/future-architect/vuls/issues/165)
- error thrown from 'docker build .' [\#157](https://github.com/future-architect/vuls/issues/157)
- CVE-ID is truncated to 4 digits [\#153](https://github.com/future-architect/vuls/issues/153)
- 'yum update --changelog' stalled in 'vuls scan'. if ssh user is not 'root'. [\#150](https://github.com/future-architect/vuls/issues/150)
- Panic on packet scan [\#131](https://github.com/future-architect/vuls/issues/131)
- Update glide.lock \#170 [\#171](https://github.com/future-architect/vuls/pull/171) ([kotakanbe](https://github.com/kotakanbe))
- Fix detecting a platform on Azure [\#168](https://github.com/future-architect/vuls/pull/168) ([kotakanbe](https://github.com/kotakanbe))
- Fix parse error for yum check-update \#165 [\#166](https://github.com/future-architect/vuls/pull/166) ([kotakanbe](https://github.com/kotakanbe))
- Fix bug: Vuls on Docker [\#159](https://github.com/future-architect/vuls/pull/159) ([tjinjin](https://github.com/tjinjin))
- Fix CVE-ID is truncated to 4 digits [\#155](https://github.com/future-architect/vuls/pull/155) ([usiusi360](https://github.com/usiusi360))
- Fix yum update --changelog stalled when non-root ssh user on CentOS \#150 [\#151](https://github.com/future-architect/vuls/pull/151) ([kotakanbe](https://github.com/kotakanbe))

**Closed issues:**

- Support su for root privilege escalation [\#44](https://github.com/future-architect/vuls/issues/44)
- Support FreeBSD [\#34](https://github.com/future-architect/vuls/issues/34)

**Merged pull requests:**

- Change scripts for data fetching from jvn [\#164](https://github.com/future-architect/vuls/pull/164) ([kotakanbe](https://github.com/kotakanbe))
- Fix: setup vulsrepo [\#162](https://github.com/future-architect/vuls/pull/162) ([tjinjin](https://github.com/tjinjin))
- Fix-docker-vulsrepo-install [\#160](https://github.com/future-architect/vuls/pull/160) ([usiusi360](https://github.com/usiusi360))
- Reduce regular expression compilation [\#158](https://github.com/future-architect/vuls/pull/158) ([itchyny](https://github.com/itchyny))
- Add testcases for \#153 [\#156](https://github.com/future-architect/vuls/pull/156) ([kotakanbe](https://github.com/kotakanbe))

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
- Typo fix and updated readme [\#19](https://github.com/future-architect/vuls/pull/19) ([EuanKerr](https://github.com/EuanKerr))
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