# Vuls on Docker

## What's Vuls-On-Docker

- 数個のコマンドを実行するだけでVulsとvulsrepoのセットアップが出来るスクリプト
- Dockerコンテナ上にVulsと[vulsrepo](https://github.com/usiusi360/vulsrepo)をセットアップ可能
- スキャン結果をvulsrepoでブラウザで分析可能
- 脆弱性データベースの更新が可能
- モジュールのアップデートが可能

## Setting up your machine
	
1. [Install Docker](https://docs.docker.com/engine/installation/)
2. [Install Docker-Compose](https://docs.docker.com/compose/install/)
3. 実行前に以下のコマンドが実行可能なことを確認する

	```
	$ docker version
	$ docker-compose version
	```

4. Vulsをgit clone
	```
	mkdir work
	cd work
	git clone https://github.com/future-architect/vuls.git
	cd vuls/setup/docker
	```

## Start A Vuls Container

- 以下のコマンドを実行してコンテナをビルドする

	```
	$ docker-compose up -d
	```

## Setting up Vuls

1. スキャン対象サーバのSSH秘密鍵を保存(vuls/setup/docker/conf/)する
2. config.toml(vuls/docker/conf/config.toml) を環境に合わせて作成する
	
	```
	[servers]

  	[servers.172-31-4-82]
  	host        = "172.31.4.82"
  	user        = "ec2-user"
  	keyPath     = "conf/id_rsa"
	```

## Fetch Vulnerability database

- NVDから脆弱性データベースを取得する
	```
	$ docker exec -t vuls scripts/fetch_nvd_all.sh
	```

- レポートを日本語化する場合は、JVNから脆弱性データを取得する
	```
	$ docker exec -t vuls scripts/fetch_jvn_all.sh
	```

## Scan servers with Vuls-On-Docker

- スキャンを実行する

	```
	$ docker exec -t vuls vuls prepare -config=conf/config.toml
	$ docker exec -t vuls scripts/scan_for_vulsrepo.sh
	```

## See the results in a browser 

```
http://${Vuls_Host}/vulsrepo/
```

# Update modules

- vuls, go-cve-dictionary, vulsrepoのモジュールをアップデートする
	```
	$ docker exec -t vuls scripts/update_modules.sh
	```

# Update Vulnerability database

- NVDの過去２年分の脆弱性データベースを更新する
	```
	$ docker exec -t vuls scripts/fetch_nvd_last2y.sh
	```

- JVNの過去１ヶ月分の脆弱性データベースを更新する
	```
	$ docker exec -t vuls scripts/fetch_jvn_month.sh
	```

- JVNの過去1週間分の脆弱性データベースを更新する
	```
	$ docker exec -t vuls scripts/fetch_jvn_week.sh
	```
