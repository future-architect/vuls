module github.com/future-architect/vuls

go 1.14

replace (
	gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.0
	gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.6
)

require (
	github.com/Azure/azure-sdk-for-go v43.3.0+incompatible
	github.com/BurntSushi/toml v0.3.1
	github.com/RackSec/srslog v0.0.0-20180709174129-a4725f04ec91
	github.com/aquasecurity/fanal v0.0.0-20200615091807-df25cfa5f9af
	github.com/aquasecurity/trivy v0.9.1
	github.com/aquasecurity/trivy-db v0.0.0-20200616161554-cd5b3da29bc8
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a
	github.com/aws/aws-sdk-go v1.33.21
	github.com/boltdb/bolt v1.3.1
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/d4l3k/messagediff v1.2.2-0.20190829033028-7e0a312ae40b
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21
	github.com/emersion/go-smtp v0.13.0
	github.com/google/subcommands v1.2.0
	github.com/gosuri/uitable v0.0.4
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/go-version v1.2.1
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/jesseduffield/gocui v0.3.0
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-cpe v0.0.0-20180327054844-659663f6eca2
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/go-version v1.1.1
	github.com/knqyf263/gost v0.1.4
	github.com/kotakanbe/go-cve-dictionary v0.5.0
	github.com/kotakanbe/go-pingscanner v0.1.0
	github.com/kotakanbe/goval-dictionary v0.2.10
	github.com/kotakanbe/logrus-prefixed-formatter v0.0.0-20180123152602-928f7356cb96
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mozqnet/go-exploitdb v0.1.0
	github.com/nlopes/slack v0.6.0
	github.com/nsf/termbox-go v0.0.0-20200418040025-38ba6e5628f1 // indirect
	github.com/olekukonko/tablewriter v0.0.4
	github.com/parnurzeal/gorequest v0.2.16
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/afero v1.3.0
	github.com/spf13/cobra v1.0.0
	github.com/takuzoo3868/go-msfdb v0.1.1
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b // indirect
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
	k8s.io/utils v0.0.0-20200619165400-6e3d28b6ed19
)
