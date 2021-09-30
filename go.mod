module github.com/future-architect/vuls

go 1.17

require (
	github.com/Azure/azure-sdk-for-go v50.2.0+incompatible
	github.com/BurntSushi/toml v0.4.1
	github.com/Ullaakut/nmap/v2 v2.1.2-0.20210406060955-59a52fe80a4f
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/aquasecurity/fanal v0.0.0-20210815095355-42429a80d0e3
	github.com/aquasecurity/trivy v0.19.3-0.20210909113250-19c0b70d2613
	github.com/aquasecurity/trivy-db v0.0.0-20210809142931-da8e09204404
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d
	github.com/aws/aws-sdk-go v1.40.22
	github.com/boltdb/bolt v1.3.1
	github.com/briandowns/spinner v1.16.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cheggaaa/pb/v3 v3.0.8 // indirect
	github.com/d4l3k/messagediff v1.2.2-0.20190829033028-7e0a312ae40b
	github.com/emersion/go-sasl v0.0.0-20200509203442-7bfe0ed36a21
	github.com/emersion/go-smtp v0.14.0
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-redis/redis/v8 v8.11.3 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/google/subcommands v1.2.0
	github.com/gosuri/uitable v0.0.4
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/go-version v1.3.0
	github.com/howeyc/gopass v0.0.0-20190910152052-7cb4b85ec19c
	github.com/jesseduffield/gocui v0.3.0
	github.com/k0kubun/pp v3.0.1+incompatible
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-cpe v0.0.0-20201213041631-54f6ab28673f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/kotakanbe/go-pingscanner v0.1.0
	github.com/kotakanbe/logrus-prefixed-formatter v0.0.0-20180123152602-928f7356cb96
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/mitchellh/go-homedir v1.1.0
	github.com/nlopes/slack v0.6.0
	github.com/nsf/termbox-go v0.0.0-20200418040025-38ba6e5628f1 // indirect
	github.com/olekukonko/tablewriter v0.0.5
	github.com/parnurzeal/gorequest v0.2.16
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/rifflock/lfshook v0.0.0-20180920164130-b9218ef580f5
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.6.0
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/cobra v1.2.1
	github.com/vulsio/go-cve-dictionary v0.8.1
	github.com/vulsio/go-exploitdb v0.4.0
	github.com/vulsio/go-msfdb v0.2.1-0.20210928020521-9b56a938f544
	github.com/vulsio/gost v0.4.1-0.20210928234623-3e6372ba2821
	github.com/vulsio/goval-dictionary v0.6.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210902165921-8d991716f632 // indirect
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
	gopkg.in/ini.v1 v1.63.2 // indirect
	gorm.io/driver/mysql v1.1.2 // indirect
	gorm.io/driver/postgres v1.1.2 // indirect
	gorm.io/driver/sqlite v1.1.5 // indirect
	k8s.io/utils v0.0.0-20210111153108-fddb29f9d009
)

require (
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.1 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.5 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.0 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/PuerkitoBio/goquery v1.7.1 // indirect
	github.com/andybalholm/cascadia v1.2.0 // indirect
	github.com/aquasecurity/go-dep-parser v0.0.0-20210815080135-5be65146849a // indirect
	github.com/aquasecurity/go-gem-version v0.0.0-20201115065557-8eed6fe000ce // indirect
	github.com/aquasecurity/go-npm-version v0.0.0-20201110091526-0b796d180798 // indirect
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46 // indirect
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/caarlos0/env/v6 v6.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/form3tech-oss/jwt-go v3.2.2+incompatible // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-github/v33 v33.0.0 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/google/wire v0.4.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/grokify/html-strip-tags-go v0.0.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.8 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/htcat/htcat v1.0.2 // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/log15 v0.0.0-20201112154412-8562bdadbbac // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.10.0 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.1.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.8.1 // indirect
	github.com/jackc/pgx/v4 v4.13.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.2 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/masahiro331/go-mvn-version v0.0.0-20210429150710-d3157d602a08 // indirect
	github.com/mattn/go-colorable v0.1.11 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/mitchellh/copystructure v1.1.1 // indirect
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/mitchellh/reflectwalk v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.9.0 // indirect
	github.com/stretchr/objx v0.3.0 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/ymomoi/goval-parser v0.0.0-20170813122243-0a0be1dd9d08 // indirect
	go.etcd.io/bbolt v1.3.6 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/sys v0.0.0-20210927094055-39ccf1dd6fa6 // indirect
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	gorm.io/gorm v1.21.15 // indirect
	moul.io/http2curl v1.0.0 // indirect
)
