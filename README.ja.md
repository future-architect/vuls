
# Vuls: VULnerability Scanner

Vulnerability scanner for Linux, agentless, written in golang.

Slackチームは[こちらから](http://goo.gl/forms/xm5KFo35tu)参加できます。(日本語でオッケーです)

[![asciicast](https://asciinema.org/a/bazozlxrw1wtxfu9yojyihick.png)](https://asciinema.org/a/bazozlxrw1wtxfu9yojyihick)

![Vuls-slack](img/vuls-slack-ja.png)


[README in English](https://github.com/future-architect/vuls/blob/master/README.md)


----

# Abstract

- 毎日のように発見される脆弱性の調査、ソフトウェアアップデート作業はシステム管理者にとって大変なタスクである
- サービス停止リスクを恐れてパッケージマネージャの自動アップデート機能を使わずに手動で行うケースも多いが、手動での運用には以下の問題がある
    - NVDやJVNなどの脆弱性データベースの新着情報をウォッチするのが大変
    - サーバにインストールされているソフトウェアは膨大であり、全てを人が把握するのは困難
    - 特にサーバ台数が多い場合は、新たに発見された脆弱性が自分の管理するどのサーバに該当するのかの調査コストが大きく、また漏れる可能性がある
    - 最新情報を見逃したら脆弱性が放置されたままになる

- Vulsはサーバに存在する脆弱性を自動スキャンし、詳細情報をレポートする
    - システムに関係あるもののみ教えてくれる
    - その脆弱性に該当するサーバを教えてくれる
    - 自動スキャンのため脆弱性対策漏れを防ぐことができる
    - CRONなどで定期実行、レポートすることで脆弱性放置を防ぐことできる

- Vulsはシステム管理者の日々の脆弱性対応を助け、システムをセキュアに保つために有用なツールとなることを目指している

![Vuls-Motivation](img/vuls-motivation.png)

----

# Main Features

- Linuxサーバに存在する脆弱性をスキャン
    - Ubuntu, Debian, CentOS, Amazon Linux, RHELに対応
    - クラウド、オンプレミス、Docker
- OSパッケージ管理対象外のミドルウェアをスキャン
    - プログラミング言語のライブラリやフレームワーク、ミドルウェアの脆弱性スキャン
    - CPEに登録されているソフトウェアが対象
- エージェントレスアーキテクチャ
    - スキャン対象サーバにSSH接続可能なマシン1台にセットアップするだけで動作
    - 複数のSSH認証方式をサポート
        - SSH agent
        - SSH public key authentication (with password, empty password)
        - Password authentication
- 設定ファイルのテンプレート自動生成
    - CIDRを指定してサーバを自動検出、設定ファイルのテンプレートを生成
- EmailやSlackで通知可能（日本語でのレポートも可能）
- 付属するTerminal-Based User Interfaceビューアでは、Vim風キーバインドでスキャン結果を参照可能

----

# レポートの日本語化

- JVNから日本語の脆弱性情報を取得
    ```
    $ go-cve-dictionary fetchjvn -help
    fetchjvn:
            fetchjvn [-dump-path=$PWD/cve] [-dpath=$PWD/vuls.sqlite3] [-week] [-month] [-entire]

      -dbpath string
            /path/to/sqlite3/DBfile (default "$PWD/cve.sqlite3")
      -debug
            debug mode
      -debug-sql
            SQL debug mode
      -dump-path string
            /path/to/dump.json (default "$PWD/cve.json")
      -entire
            Fetch data for entire period.(This operation is time-consuming) (default: false)
      -month
            Fetch data in the last month (default: false)
      -week
            Fetch data in the last week. (default: false)

    ```

- すべての期間の脆弱性情報を取得(1時間以上かかる)
    ```
    $ go-cve-dictionary fetchjvn -entire
    ```

- 直近1ヶ月間に更新された脆弱性情報を取得(1分未満)
    ```
    $ go-cve-dictionary fetchjvn -month
    ```

- 直近1週間に更新された脆弱性情報を取得(1分未満)
    ```
    $ go-cve-dictionary fetchjvn -week
    ```

- 脆弱性情報の自動アップデート  
Cronなどのジョブスケジューラを用いて実現可能。  
-week オプションを指定して夜間の日次実行を推奨。


## スキャン実行

```
$ vuls scan -lang=ja
```
Scan時にlang=jaを指定すると脆弱性レポートが日本語になる  
slack, emailは日本語対応済み TUIは日本語表示未対応

