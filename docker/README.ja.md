# Vuls on Docker

## Index

- テスト環境
- サーバーセットアップ
    - Dockerのインストール
    - Docker Composeのインストール
- vulsセットアップ
    - sshキーの配置
    - tomlの編集
- Vuls 起動
- Vuls scan実行
- ブラウザから動作確認


##テスト環境

- Server OS: ubuntu 14.04

## サーバーセットアップ

1. Dockerのインストール
2. Docker Composeのインストール

### 作業ディレクトリの作成

```
mkdir work
cd work
git clone https://github.com/hikachan/vuls
cd vuls
```

## Vuls セットアップ

### sshキーの配置(vuls/docker/conf/id_rsa)

### tomlの編集(vuls/docker/conf/config.toml)

```
[servers]

#This is a sample
[servers.172.17.0.1]
host         = "172.17.0.1"
port        = "22"
user        = "ubuntu"
keyPath     = "/root/.ssh/id_rsa"
#containers = ["target_container"]
```

## Vuls 起動

```
docker-compose up -d
```

## Update cve

```
docker exec -t vuls scripts/update_cve.sh
```

## Vuls Scan 実行

```
docker exec -t vuls vuls prepare -config=conf/config.toml
docker exec -t vuls scripts/scan_for_vulsrepo.sh
```

### Vuls Repo 接続確認

```
http://${Vuls_Host}/vulsrepo/
```

