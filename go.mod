module github.com/future-architect/vuls

go 1.12

require (
	cloud.google.com/go v0.41.0 // indirect
	contrib.go.opencensus.io/exporter/ocagent v0.4.12 // indirect
	github.com/Azure/azure-sdk-for-go v28.1.0+incompatible
	github.com/Azure/go-autorest v12.0.0+incompatible // indirect
	github.com/BurntSushi/toml v0.3.1
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a
	github.com/aws/aws-sdk-go v1.19.24
	github.com/boltdb/bolt v1.3.1
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/dnaeon/go-vcr v1.0.1 // indirect
	github.com/elazarl/goproxy v0.0.0-20190703090003-6125c262ffb0 // indirect
	github.com/elazarl/goproxy/ext v0.0.0-20190703090003-6125c262ffb0 // indirect
	github.com/genuinetools/reg v0.16.1 // indirect
	github.com/google/subcommands v1.0.1
	github.com/gopherjs/gopherjs v0.0.0-20190430165422-3e4dfb77656c // indirect
	github.com/gosuri/uitable v0.0.1
	github.com/grpc-ecosystem/grpc-gateway v1.9.3 // indirect
	github.com/hashicorp/go-version v1.2.0
	github.com/hashicorp/uuid v0.0.0-20160311170451-ebb0a03e909c
	github.com/howeyc/gopass v0.0.0-20170109162249-bf9dde6d0d2c
	github.com/jroimartin/gocui v0.4.0
	github.com/k0kubun/colorstring v0.0.0-20150214042306-9440f1994b88 // indirect
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/knqyf263/fanal v0.0.0-20190706175150-0e953d070757
	github.com/knqyf263/go-cpe v0.0.0-20180327054844-659663f6eca2
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-dep-parser v0.0.0-20190521150559-1ef8521d17a0
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/go-version v1.1.1
	github.com/knqyf263/gost v0.1.2
	github.com/knqyf263/trivy v0.1.4
	github.com/kotakanbe/go-cve-dictionary v0.0.0-20190327053454-5fe52611f0b8
	github.com/kotakanbe/go-pingscanner v0.1.0
	github.com/kotakanbe/goval-dictionary v0.2.0
	github.com/kotakanbe/logrus-prefixed-formatter v0.0.0-20180123152602-928f7356cb96
	github.com/lusis/go-slackbot v0.0.0-20180109053408-401027ccfef5 // indirect
	github.com/lusis/slack-test v0.0.0-20190426140909-c40012f20018 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozqnet/go-exploitdb v0.0.0-20190426034301-a055cc2c195d
	github.com/nlopes/slack v0.4.0
	github.com/nsf/termbox-go v0.0.0-20190325093121-288510b9734e // indirect
	github.com/olekukonko/tablewriter v0.0.2-0.20190607075207-195002e6e56a
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/parnurzeal/gorequest v0.2.15
	github.com/pelletier/go-toml v1.4.0 // indirect
	github.com/prometheus/common v0.6.0 // indirect
	github.com/prometheus/procfs v0.0.3 // indirect
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/assertions v1.0.0 // indirect
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	go.etcd.io/bbolt v1.3.3 // indirect
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/net v0.0.0-20190628185345-da137c7871d7 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sys v0.0.0-20190626221950-04f50cda93cb // indirect
	golang.org/x/xerrors v0.0.0-20190410155217-1f06c39b4373
	google.golang.org/genproto v0.0.0-20190701230453-710ae3a149df // indirect
	google.golang.org/grpc v1.22.0 // indirect
	gopkg.in/mattn/go-colorable.v0 v0.1.2 // indirect
	gopkg.in/mattn/go-isatty.v0 v0.0.8 // indirect
)

replace github.com/genuinetools/reg => github.com/tomoyamachi/reg v0.16.1-0.20190706172545-2a2250fd7c00

replace gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.0

replace gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.6
