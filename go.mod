module github.com/future-architect/vuls

go 1.15

replace (
	gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.0
	gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.6
)

require (
	github.com/Azure/azure-sdk-for-go v50.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.16 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.10 // indirect
	github.com/BurntSushi/toml v0.3.1
	github.com/aquasecurity/fanal v0.0.0-20210111044704-9cb28297c870
	github.com/aquasecurity/go-dep-parser v0.0.0-20210113052454-251388ce94e5 // indirect
	github.com/aquasecurity/trivy v0.15.0
	github.com/aquasecurity/trivy-db v0.0.0-20210111152553-7d4d1aa5f0d4
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/aws/aws-sdk-go v1.36.26
	github.com/boltdb/bolt v1.3.1
	github.com/caarlos0/env/v6 v6.4.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/d4l3k/messagediff v1.2.2-0.20190829033028-7e0a312ae40b
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21
	github.com/emersion/go-smtp v0.14.0
	github.com/go-redis/redis/v8 v8.4.8 // indirect
	github.com/goccy/go-yaml v1.8.4 // indirect
	github.com/golang/protobuf v1.4.3 // indirect
	github.com/google/subcommands v1.2.0
	github.com/google/wire v0.4.0 // indirect
	github.com/gosuri/uitable v0.0.4
	github.com/grokify/html-strip-tags-go v0.0.1 // indirect
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/go-version v1.2.1
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/jesseduffield/gocui v0.3.0
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-cpe v0.0.0-20201213041631-54f6ab28673f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/knqyf263/gost v0.1.7
	github.com/kotakanbe/go-cve-dictionary v0.5.6
	github.com/kotakanbe/go-pingscanner v0.1.0
	github.com/kotakanbe/goval-dictionary v0.3.0
	github.com/kotakanbe/logrus-prefixed-formatter v0.0.0-20180123152602-928f7356cb96
	github.com/magiconair/properties v1.8.4 // indirect
	github.com/mattn/go-runewidth v0.0.10 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/mozqnet/go-exploitdb v0.1.2
	github.com/nlopes/slack v0.6.0
	github.com/nsf/termbox-go v0.0.0-20201124104050-ed494de23a00 // indirect
	github.com/olekukonko/tablewriter v0.0.4
	github.com/parnurzeal/gorequest v0.2.16
	github.com/pelletier/go-toml v1.8.1 // indirect
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/afero v1.5.1
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/cobra v1.1.1
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.7.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/takuzoo3868/go-msfdb v0.1.3
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0 // indirect
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/lint v0.0.0-20201208152925-83fdc39ff7b5 // indirect
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b // indirect
	golang.org/x/oauth2 v0.0.0-20210113205817-d3ed898aa8a3
	golang.org/x/sys v0.0.0-20210113181707-4bcb84eeeb78 // indirect
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
	golang.org/x/text v0.3.5 // indirect
	golang.org/x/tools v0.0.0-20201211185031-d93e913c1a58 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	honnef.co/go/tools v0.1.0 // indirect
	k8s.io/utils v0.0.0-20210111153108-fddb29f9d009
)
