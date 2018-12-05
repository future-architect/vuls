package alert

// Alert has XCERT alert information
type Alert struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Team  string `json:"team"`
}

// AlertDictJa has JPCERT alerts
var AlertDictJa = map[string]Alert{
	"https://www.jpcert.or.jp/at/199x/97-0001-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/97-0001-01.html",
		Title: `年末年始休暇中に多発したアタックについて`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/97-0002-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/97-0002-01.html",
		Title: `ネットワークニュースのサービスを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/97-0003-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/97-0003-01.html",
		Title: `phf CGI プログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/97-0004-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/97-0004-01.html",
		Title: `IMAP サーバー・プログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/98-0001-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/98-0001-01.html",
		Title: `statd サーバプログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/98-0002-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/98-0002-01.html",
		Title: `named サーバプログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/98-0003-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/98-0003-01.html",
		Title: `POP サーバプログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/98-0004-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/98-0004-01.html",
		Title: `ポートスキャンを用いた不正アクセス`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/99-0001-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/99-0001-01.html",
		Title: `NFS マウントデーモン mountd を悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/199x/99-0002-01.html": {
		URL:   "https://www.jpcert.or.jp/at/199x/99-0002-01.html",
		Title: `automountdサーバプログラムを悪用したアタック`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000001.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000001.html",
		Title: `IMAP から POP2 への変換サーバプログラムについて`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000002.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000002.html",
		Title: `年末年始休暇中に多発したアタックについて(Version 4)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000003.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000003.html",
		Title: `phf CGIプログラムを悪用したアタック(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000004.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000004.html",
		Title: `ネットワークニュースのサービスを悪用したアタック(Version 4)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000005.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000005.html",
		Title: `statd サーバプログラムを悪用したアタック(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000006.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000006.html",
		Title: `named サーバプログラムを悪用したアタック(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000007.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000007.html",
		Title: `ポートスキャンを用いた不正アクセス(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000008.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000008.html",
		Title: `IMAP サーバー・プログラムを悪用したアタック(Version 3)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000009.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000009.html",
		Title: `NFS マウントデーモン mountdを悪用したアタック(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000010.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000010.html",
		Title: `POP サーバプログラムを悪用したアタック(Version 4)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000011.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000011.html",
		Title: `automountd サーバプログラムを悪用したアタック(Version 3)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2000/at000012.html": {
		URL:   "https://www.jpcert.or.jp/at/2000/at000012.html",
		Title: `IMAP から POP2 への変換サーバプログラムについて(Version 2)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010001.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010001.html",
		Title: `Webページ改ざんに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010002.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010002.html",
		Title: `DDoS の踏台および BIND などのセキュリティ上の弱点に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010003.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010003.html",
		Title: `BIND のセキュリティ上の弱点に関する注意喚起(続報)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010004.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010004.html",
		Title: `Linux Worm に関する緊急報告`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010005.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010005.html",
		Title: `Microsoft IIS バージョン5.0のセキュリティ上の問題について`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010006.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010006.html",
		Title: `Microsoft IIS バージョン5.0のセキュリティ上の問題について(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010007.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010007.html",
		Title: `Solaris に感染し Microsoft IIS を攻撃するワームに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010008.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010008.html",
		Title: `Microsoft IIS バージョン5.0のセキュリティ上の問題について(URLの訂正)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010009.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010009.html",
		Title: `Solaris に侵入し Microsoft IIS を攻撃するワーム`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010010.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010010.html",
		Title: `Microsoft IIS Index Server に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010011.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010011.html",
		Title: `Solaris の プリンタデーモンに含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010012.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010012.html",
		Title: `Solaris の NIS プログラム ypbind に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010013.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010013.html",
		Title: `注意喚起(2001-07-19 公開)のタイトルにおける不整合を修正`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010014.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010014.html",
		Title: `Microsoft IIS の脆弱性を使って伝播するワーム`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010015.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010015.html",
		Title: `SSH のパスワード認証の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010016.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010016.html",
		Title: `telnetd に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010017.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010017.html",
		Title: `Code RedWorm の伝播活動再開に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010018.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010018.html",
		Title: `Microsoft IIS の脆弱性を使って伝播するワーム(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010019.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010019.html",
		Title: `Code RedWorm の変種に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010020.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010020.html",
		Title: `Microsoft IIS の脆弱性を使って伝播するワーム"Code Red II"(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010021.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010021.html",
		Title: `Linux の telnetd に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010022.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010022.html",
		Title: `BSD 系 OS の lpd に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010023.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010023.html",
		Title: `80番ポート(HTTP)へのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2001/at010024.html": {
		URL:   "https://www.jpcert.or.jp/at/2001/at010024.html",
		Title: `CDE ToolTalkに含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020001.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020001.html",
		Title: `SNMPv1 の実装に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020002.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020002.html",
		Title: `TCP 1433番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020003.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020003.html",
		Title: `Apache Web サーバプログラムの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020004.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020004.html",
		Title: `OpenSSH サーバプログラムの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020005.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020005.html",
		Title: `DNS resolver の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2002/at020006.html": {
		URL:   "https://www.jpcert.or.jp/at/2002/at020006.html",
		Title: `OpenSSL の脆弱性を使って伝播する Apache/mod sslワーム(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030001.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030001.html",
		Title: `UDP 1434番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030002.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030002.html",
		Title: `sendmailの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030003.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030003.html",
		Title: `Microsoft IIS 5.0 の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030004.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030004.html",
		Title: `新たな sendmail の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030005.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030005.html",
		Title: `TCP 135番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030006.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030006.html",
		Title: `Windows RPC の脆弱性を使用するワームに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2003/at030007.html": {
		URL:   "https://www.jpcert.or.jp/at/2003/at030007.html",
		Title: `TCP 139番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040001.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040001.html",
		Title: `Microsoft ASN.1 Libraryの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040002.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040002.html",
		Title: `Netsky.Q のサービス運用妨害攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040003.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040003.html",
		Title: `TCP プロトコルに潜在する信頼性の問題(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040004.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040004.html",
		Title: `CISCO IOSにおけるSNMPメッセージ処理の脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040005.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040005.html",
		Title: `Windowsに含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040006.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040006.html",
		Title: `Windows LSASS の脆弱性を使って伝播するワームW32/Sasser`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040007.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040007.html",
		Title: `IEEE 802.11 DSSS 無線機器におけるDoS の脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040008.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040008.html",
		Title: `キーボード入力などを記録し外部に送信するプログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040009.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040009.html",
		Title: `Juniper JUNOS PFE の IPv6 処理にメモリリークの脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040010.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040010.html",
		Title: `libpngに複製の脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2004/at040011.html": {
		URL:   "https://www.jpcert.or.jp/at/2004/at040011.html",
		Title: `phpBBの脆弱性を使って伝播するワームに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050001.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050001.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050002.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050002.html",
		Title: `Web 偽装詐欺(phishing)の踏み台サーバに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050003.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050003.html",
		Title: `OpenSSHの脆弱性を使ったシステムへの侵入に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050004.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050004.html",
		Title: `VERITAS Backup Exec に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050005.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050005.html",
		Title: `DNS サーバの設定とドメイン名の登録に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050006.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050006.html",
		Title: `TCP 1433番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050007.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050007.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050008.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050008.html",
		Title: `Microsoft製品の脆弱性を使って伝播するワームに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050009.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050009.html",
		Title: `Snort Back Orifice preprocessorの脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050010.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050010.html",
		Title: `Internet Explorer の JavaScriptの脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050011.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050011.html",
		Title: `Sober ワームの変種に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050012.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050012.html",
		Title: `TCP 1025番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050013.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050013.html",
		Title: `Microsoft Internet Explorer に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2005/at050014.html": {
		URL:   "https://www.jpcert.or.jp/at/2005/at050014.html",
		Title: `Microsoft Windows メタファイル処理の脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060001.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060001.html",
		Title: `Microsoft Windows メタファイル処理の脆弱性に対するセキュリティ更新プログラムについて`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060002.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060002.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060003.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060003.html",
		Title: `sendmailの脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060004.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060004.html",
		Title: `DNS の再帰的な問合せを使った　DDoS 攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060005.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060005.html",
		Title: `RealVNC サーバの認証が回避される脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060006.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060006.html",
		Title: `Microsoft Wordの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060007.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060007.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060008.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060008.html",
		Title: `sendmail の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060009.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060009.html",
		Title: `Microsoft Excel 未修正の脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060010.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060010.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060011.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060011.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060012.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060012.html",
		Title: `TCP 139番ポートへのスキャン増加に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060013.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060013.html",
		Title: `夏季休暇明けの対応について(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060014.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060014.html",
		Title: `Microsoft 製品に含まれる脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060015.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060015.html",
		Title: `Microsoft Windows VML の処理に未修正の脆弱性(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060016.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060016.html",
		Title: `Microsoft PowerPoint 未修正の脆弱性 に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060017.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060017.html",
		Title: `2006年10月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060018.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060018.html",
		Title: `Microsoft XML コアサービスに未修正の脆弱性(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060019.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060019.html",
		Title: `2006年11月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060020.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060020.html",
		Title: `2006年12月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2006/at060021.html": {
		URL:   "https://www.jpcert.or.jp/at/2006/at060021.html",
		Title: `TCP 2967番ポートへのスキャン増加に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070001.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070001.html",
		Title: `2007年1月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070002.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070002.html",
		Title: `Cisco IOS に複数の脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070003.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070003.html",
		Title: `Cisco IOS の SIP パケットの処理に関する脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070004.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070004.html",
		Title: `「CCCクリーナー」の脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070005.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070005.html",
		Title: `2007年2月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070006.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070006.html",
		Title: `ベリサイン マネージドPKIサービスに使用される ActiveXコントロールの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070007.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070007.html",
		Title: `Sun Solaris in.telnetd の脆弱性を使用するワームに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070008.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070008.html",
		Title: `Windows アニメーション カーソル処理の未修正の脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070009.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070009.html",
		Title: `国内金融機関を装ったフィッシングサイトに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070010.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070010.html",
		Title: `2007年4月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070011.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070011.html",
		Title: `Java Web Start の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070012.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070012.html",
		Title: `2007年5月 Microsoft セキュリティ情報 (緊急 7件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070013.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070013.html",
		Title: `複数の Cisco製品におけるDos の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070014.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070014.html",
		Title: `2007年6月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070015.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070015.html",
		Title: `IDやパスワードを聞き出そうとする電話に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070016.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070016.html",
		Title: `複数の脆弱性を使用する攻撃ツール MPackに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070017.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070017.html",
		Title: `2007年7月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070018.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070018.html",
		Title: `2007年8月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070019.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070019.html",
		Title: `TCP 5168番ポートへのスキャン増加に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070020.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070020.html",
		Title: `ファイル圧縮・解凍ソフトLhaplusの脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070021.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070021.html",
		Title: `2007年10月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070022.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070022.html",
		Title: `2007年11月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070023.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070023.html",
		Title: `アップルQuick Timeの未修正の脆弱性に関する注意喚起(更新)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2007/at070024.html": {
		URL:   "https://www.jpcert.or.jp/at/2007/at070024.html",
		Title: `2007年12月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080001.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080001.html",
		Title: `2008年1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080002.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080002.html",
		Title: `国内ブランドを装ったフィッシングサイトに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080003.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080003.html",
		Title: `2008年2月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080004.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080004.html",
		Title: `2008年3月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080005.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080005.html",
		Title: `SQL インジェクションによる Web サイト改ざんに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080006.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080006.html",
		Title: `2008年4月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080007.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080007.html",
		Title: `2008年5月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080008.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080008.html",
		Title: `Debian GNU/Linux に含まれる OpenSSL/OpenSSH の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080009.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080009.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080010.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080010.html",
		Title: `2008年6月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080011.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080011.html",
		Title: `SNMPv3 を実装した複数製品の認証回避の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080012.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080012.html",
		Title: `Adobe Acrobat 及び Adobe Reader の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080013.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080013.html",
		Title: `複数の DNS サーバ製品におけるキャッシュポイズニングの脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080014.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080014.html",
		Title: `[続報] 複数の DNS サーバ製品におけるキャッシュポイズニングの脆弱性`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080015.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080015.html",
		Title: `2008年8月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080016.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080016.html",
		Title: `2008年9月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080017.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080017.html",
		Title: `2008年10月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080018.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080018.html",
		Title: `Microsoft Server サービスの脆弱性 (MS08-067) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080019.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080019.html",
		Title: `TCP 445番ポートへのスキャン増加に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080020.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080020.html",
		Title: `Adobe Acrobat 及び Adobe Reader の脆弱性に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080021.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080021.html",
		Title: `2008年11月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080022.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080022.html",
		Title: `2008年12月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2008/at080023.html": {
		URL:   "https://www.jpcert.or.jp/at/2008/at080023.html",
		Title: `Microsoft Internet Explorer の脆弱性(MS08-078)に関する注意喚起(公開)`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090001.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090001.html",
		Title: `2009年1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090002.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090002.html",
		Title: `[続報]TCP 445番ポートへのスキャン増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090003.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090003.html",
		Title: `2009年2月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090004.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090004.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090005.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090005.html",
		Title: `2009年3月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090006.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090006.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090007.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090007.html",
		Title: `2009年4月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090008.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090008.html",
		Title: `2009年5月 Microsoft セキュリティ情報 (緊急 1件) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090009.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090009.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090010.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090010.html",
		Title: `JavaScript が埋め込まれる Web サイトの改ざんに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090011.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090011.html",
		Title: `2009年6月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090012.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090012.html",
		Title: `韓国、米国で発生している DDoS 攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090013.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090013.html",
		Title: `2009年7月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090014.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090014.html",
		Title: `Microsoft ATL を使用した複数製品の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090015.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090015.html",
		Title: `Adobe Flash Player および Adobe Acrobat/Reader の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090016.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090016.html",
		Title: `ISC BIND 9 の脆弱性を使用したサービス運用妨害攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090017.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090017.html",
		Title: `2009年8月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090018.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090018.html",
		Title: `2009年9月 Microsoft セキュリティ情報 (緊急 5件) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090019.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090019.html",
		Title: `複数製品の TCP プロトコルの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090020.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090020.html",
		Title: `2009年10月 Microsoft セキュリティ情報 (緊急 8件) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090021.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090021.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090022.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090022.html",
		Title: `マイクロソフト社を騙るマルウエア添付メールに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090023.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090023.html",
		Title: `Web サイト経由でのマルウエア感染拡大に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090024.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090024.html",
		Title: `2009年11月 Microsoft セキュリティ情報 (緊急 3件) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090025.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090025.html",
		Title: `2009年12月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090026.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090026.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2009/at090027.html": {
		URL:   "https://www.jpcert.or.jp/at/2009/at090027.html",
		Title: `Adobe Reader 及び Acrobat の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100001.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100001.html",
		Title: `Web サイト改ざん及びいわゆる Gumblar ウイルス感染拡大に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100002.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100002.html",
		Title: `2010年1月 Microsoft セキュリティ情報 (緊急 1件) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100003.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100003.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100004.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100004.html",
		Title: `Microsoft Internet Explorer の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100005.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100005.html",
		Title: `FTP アカウント情報を盗むマルウエアに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100006.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100006.html",
		Title: `2010年2月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100007.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100007.html",
		Title: `Microsoft Internet Explorer の脆弱性 (MS10-018) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100008.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100008.html",
		Title: `2010年4月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100009.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100009.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100010.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100010.html",
		Title: `Oracle Sun JDK および JRE の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100011.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100011.html",
		Title: `いわゆる Gumblar ウイルスによってダウンロードされる DDoS 攻撃を行うマルウエアに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100012.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100012.html",
		Title: `2010年5月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100013.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100013.html",
		Title: `社内 PC のマルウエア感染調査を騙るマルウエア添付メールに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100014.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100014.html",
		Title: `2010年6月  Microsoft  セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100015.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100015.html",
		Title: `Adobe Flash Player および Adobe Acrobat/Reader の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100016.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100016.html",
		Title: `Windows のヘルプとサポートセンターの未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100017.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100017.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100018.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100018.html",
		Title: `2010年7月  Microsoft   セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100019.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100019.html",
		Title: `Windows シェルの脆弱性 (MS10-046) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100020.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100020.html",
		Title: `2010年8月 Microsoft セキュリティ情報 (緊急 8件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100021.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100021.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100022.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100022.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100023.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100023.html",
		Title: `2010年9月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100024.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100024.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100025.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100025.html",
		Title: `攻撃用ツールキットを使用した Web サイト経由での攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100026.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100026.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100027.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100027.html",
		Title: `2010年10月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100028.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100028.html",
		Title: `アクセス解析サービスを使用した Web サイト経由での攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100029.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100029.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100030.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100030.html",
		Title: `2010年11月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100031.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100031.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100032.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100032.html",
		Title: `不適切な設定で Asteriskを利用した場合に発生し得る不正利用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2010/at100033.html": {
		URL:   "https://www.jpcert.or.jp/at/2010/at100033.html",
		Title: `2010年12月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110001.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110001.html",
		Title: `2011年1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110002.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110002.html",
		Title: `主に UNIX / Linux 系サーバを対象としたインターネット公開サーバのセキュリティ設定に関する注意喚起に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110003.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110003.html",
		Title: `2011年2月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110004.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110004.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110005.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110005.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110006.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110006.html",
		Title: `2011年3月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110007.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110007.html",
		Title: `Adobe Flash Player および Adobe Reader / Acrobatの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110008.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110008.html",
		Title: `2011年4月 Microsoft セキュリティ情報 (緊急 9件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110009.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110009.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110010.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110010.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110011.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110011.html",
		Title: `情報流出に伴う ID とパスワードの不正使用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110012.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110012.html",
		Title: `2011年5月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110013.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110013.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110014.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110014.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110015.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110015.html",
		Title: `Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110016.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110016.html",
		Title: `2011年6月 Microsoft セキュリティ情報 (緊急 9件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110017.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110017.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110018.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110018.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110019.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110019.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110020.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110020.html",
		Title: `2011年7月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110021.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110021.html",
		Title: `2011年8月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110022.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110022.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110023.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110023.html",
		Title: `Apache HTTP Server のサービス運用妨害の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110024.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110024.html",
		Title: `Remote Desktop (RDP) が使用する3389番ポートへのスキャンに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110025.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110025.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110026.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110026.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110027.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110027.html",
		Title: `2011年10月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110028.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110028.html",
		Title: `標的型メール攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110029.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110029.html",
		Title: `2011年11月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110030.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110030.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110031.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110031.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110032.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110032.html",
		Title: `Java SE を対象とした既知の脆弱性を狙う攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110033.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110033.html",
		Title: `2011年12月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2011/at110034.html": {
		URL:   "https://www.jpcert.or.jp/at/2011/at110034.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120001.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120001.html",
		Title: `Microsoft .NET Framework の複数の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120002.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120002.html",
		Title: `2012年1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120003.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120003.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120004.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120004.html",
		Title: `PHP 5.3.9 の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120005.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120005.html",
		Title: `2012年2月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120006.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120006.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120007.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120007.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120008.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120008.html",
		Title: `DNS 設定を書き換えるマルウエア (DNS Changer) 感染に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120009.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120009.html",
		Title: `2012年3月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120010.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120010.html",
		Title: `2012年2月公開の Java SE の脆弱性を狙う攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120011.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120011.html",
		Title: `Adobe Flash Player の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120012.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120012.html",
		Title: `2012年4月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120013.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120013.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120014.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120014.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120015.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120015.html",
		Title: `2012年5月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120016.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120016.html",
		Title: `PHP の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120017.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120017.html",
		Title: `ロジテック社製ブロードバンドルータの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120018.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120018.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120019.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120019.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-14) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120020.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120020.html",
		Title: `2012年6月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120021.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120021.html",
		Title: `2012年6月 Java SE の脆弱性を狙う攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120022.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120022.html",
		Title: `2012年7月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120023.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120023.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB12-16) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120024.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120024.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-18) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120025.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120025.html",
		Title: `2012年8月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120026.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120026.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-19) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120027.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120027.html",
		Title: `MS-CHAP v2 の認証情報漏えいの問題に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120028.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120028.html",
		Title: `2012年 8月 Java SE の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120029.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120029.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2012-4244) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120030.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120030.html",
		Title: `2012年9月 Microsoft Internet Explorer の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120031.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120031.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-22) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120032.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120032.html",
		Title: `2012年10月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120033.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120033.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2012-5166) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120034.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120034.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-24) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120035.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120035.html",
		Title: `2012年11月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120036.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120036.html",
		Title: `2012年10月公開の Java SE の脆弱性を狙う攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120037.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120037.html",
		Title: `Adobe Flash Player の脆弱性 (APSB12-27) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2012/at120038.html": {
		URL:   "https://www.jpcert.or.jp/at/2012/at120038.html",
		Title: `2012年12月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130001.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130001.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130002.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130002.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB13-02) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130003.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130003.html",
		Title: `2013年1月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130004.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130004.html",
		Title: `Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130005.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130005.html",
		Title: `Microsoft Internet Explorer の脆弱性 (MS13-008) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130006.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130006.html",
		Title: `Portable SDK for UPnP の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130007.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130007.html",
		Title: `2013年2月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130008.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130008.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-04) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130009.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130009.html",
		Title: `2013年2月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130010.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130010.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-05) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130011.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130011.html",
		Title: `2013年2月 Oracle Java SE のクリティカルパッチアップデート (定例) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130012.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130012.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB13-07) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130013.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130013.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-08) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130014.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130014.html",
		Title: `2013年3月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130015.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130015.html",
		Title: `2013年3月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130016.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130016.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130017.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130017.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2013-2266) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130018.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130018.html",
		Title: `旧バージョンの Parallels Plesk Panel の利用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130019.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130019.html",
		Title: `2013年4月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130020.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130020.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-11) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130021.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130021.html",
		Title: `2013年4月 Oracle Java SE のクリティカルパッチアップデート (定例) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130022.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130022.html",
		Title: `DNS の再帰的な問い合わせを使った DDoS 攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130023.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130023.html",
		Title: `2013年5月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130024.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130024.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB13-15) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130025.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130025.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-14) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130026.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130026.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2013-3919) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130027.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130027.html",
		Title: `Web サイト改ざんに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130028.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130028.html",
		Title: `2013年6月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130029.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130029.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-16) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130030.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130030.html",
		Title: `2013年6月 Oracle Java SE のクリティカルパッチアップデート (定例) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130031.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130031.html",
		Title: `2013年7月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130032.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130032.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-17) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130033.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130033.html",
		Title: `Apache Struts の脆弱性 (S2-016) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130034.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130034.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2013-4854) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130035.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130035.html",
		Title: `2013年8月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130036.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130036.html",
		Title: `SIP サーバの不正利用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130037.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130037.html",
		Title: `2013年9月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130038.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130038.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-21) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130039.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130039.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB13-22) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130040.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130040.html",
		Title: `2013年9月 Microsoft Internet Explorer の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130041.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130041.html",
		Title: `2013年10月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130042.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130042.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB13-25) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130043.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130043.html",
		Title: `2013年10月 Oracle Java SE のクリティカルパッチアップデート (定例) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130044.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130044.html",
		Title: `2013年11月 Microsoft Graphics Component の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130045.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130045.html",
		Title: `2013年11月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130046.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130046.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-26) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130047.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130047.html",
		Title: `2013年12月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2013/at130048.html": {
		URL:   "https://www.jpcert.or.jp/at/2013/at130048.html",
		Title: `Adobe Flash Player の脆弱性 (APSB13-28) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140001.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140001.html",
		Title: `ntpd の monlist 機能を使った DDoS 攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140002.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140002.html",
		Title: `2014年1月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140003.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140003.html",
		Title: `Adobe Reader 及び Acrobat の脆弱性 (APSB14-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140004.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140004.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-02) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140005.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140005.html",
		Title: `2014年1月 Microsoft セキュリティ情報に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140006.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140006.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-04) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140007.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140007.html",
		Title: `Apache Commons FileUpload および Apache Tomcat の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140008.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140008.html",
		Title: `2014年2月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140009.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140009.html",
		Title: `2014年2月 Microsoft Internet Explorer の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140010.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140010.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-07) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140011.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140011.html",
		Title: `2014年3月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140012.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140012.html",
		Title: `2014年3月 Microsoft Word の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140013.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140013.html",
		Title: `OpenSSL の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140014.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140014.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140015.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140015.html",
		Title: `2014年4月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140016.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140016.html",
		Title: `DNS キャッシュポイズニング攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140017.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140017.html",
		Title: `2014年4月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140018.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140018.html",
		Title: `2014年4月 Microsoft Internet Explorer の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140019.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140019.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-13) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140020.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140020.html",
		Title: `マイクロソフト セキュリティ情報(MS14-021)に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140021.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140021.html",
		Title: `2014年5月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140022.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140022.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-14) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140023.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140023.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB14-15) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140024.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140024.html",
		Title: `旧バージョンの Movable Type の利用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140025.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140025.html",
		Title: `2014年6月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140026.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140026.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-16) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140027.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140027.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2014-3859) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140028.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140028.html",
		Title: `2014年7月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140029.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140029.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-17) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140030.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140030.html",
		Title: `2014年7月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140031.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140031.html",
		Title: `2014年8月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140032.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140032.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-18) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140033.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140033.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB14-19) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140034.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140034.html",
		Title: `2014年9月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140035.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140035.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-21) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140036.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140036.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB14-20) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140037.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140037.html",
		Title: `GNU bash の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140038.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140038.html",
		Title: `TCP 10000番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140039.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140039.html",
		Title: `2014年10月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140040.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140040.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-22) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140041.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140041.html",
		Title: `2014年10月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140042.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140042.html",
		Title: `Drupal の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140043.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140043.html",
		Title: `2014年10月 Microsoft OLE の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140044.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140044.html",
		Title: `登録情報の不正書き換えによるドメイン名ハイジャックに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140045.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140045.html",
		Title: `2014年11月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140046.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140046.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-24) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140047.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140047.html",
		Title: `2014年11月一太郎シリーズの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140048.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140048.html",
		Title: `2014年11月 Kerberos KDC の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140049.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140049.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-26) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140050.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140050.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2014-8500) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140051.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140051.html",
		Title: `2014年12月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140052.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140052.html",
		Title: `Adobe Flash Player の脆弱性 (APSB14-27) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140053.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140053.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB14-28) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140054.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140054.html",
		Title: `Active Directory のドメイン管理者アカウントの不正使用に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2014/at140055.html": {
		URL:   "https://www.jpcert.or.jp/at/2014/at140055.html",
		Title: `TCP 8080番ポートへのスキャンの増加に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150001.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150001.html",
		Title: `2015年1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150002.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150002.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150003.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150003.html",
		Title: `2015年1月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150004.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150004.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-03) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150005.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150005.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-04) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150006.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150006.html",
		Title: `2015年2月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150007.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150007.html",
		Title: `2015年3月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150008.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150008.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-05) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150009.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150009.html",
		Title: `2015年4月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150010.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150010.html",
		Title: `2015年4月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150011.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150011.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-06) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150012.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150012.html",
		Title: `2015年5月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150013.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150013.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150014.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150014.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB15-10) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150015.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150015.html",
		Title: `ランサムウエア感染に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150016.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150016.html",
		Title: `2015年6月 Microsoft セキュリティ情報 (緊急 2件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150017.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150017.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-11) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150018.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150018.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-14) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150019.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150019.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-16) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150020.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150020.html",
		Title: `2015年7月 Adobe Flash Player の未修正の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150021.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150021.html",
		Title: `Cisco 社製セキュリティアプライアンスソフトウェアの 脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150022.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150022.html",
		Title: `2015年7月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150023.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150023.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB15-15) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150024.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150024.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-18) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150025.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150025.html",
		Title: `2015年7月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150026.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150026.html",
		Title: `マイクロソフト セキュリティ情報 (MS15-078) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150027.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150027.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2015-5477) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150028.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150028.html",
		Title: `2015年8月 Microsoft セキュリティ情報 (緊急 4件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150029.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150029.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-19) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150030.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150030.html",
		Title: `マイクロソフト セキュリティ情報 (MS15-093) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150031.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150031.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2015-5986) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150032.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150032.html",
		Title: `2015年9月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150033.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150033.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-23) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150034.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150034.html",
		Title: `2015年10月 Microsoft セキュリティ情報 (緊急 3件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150035.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150035.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB15-24) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150036.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150036.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-25) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150037.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150037.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-27) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150038.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150038.html",
		Title: `2015年10月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150039.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150039.html",
		Title: `2015年11月 Microsoft セキュリティ情報 (緊急 4件含) にする注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150040.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150040.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-28) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150041.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150041.html",
		Title: `2015年12月 Microsoft セキュリティ情報 (緊急 8件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150042.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150042.html",
		Title: `Adobe Flash Player の脆弱性 (APSB15-32) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2015/at150043.html": {
		URL:   "https://www.jpcert.or.jp/at/2015/at150043.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2015-8000) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160001.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160001.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160002.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160002.html",
		Title: `DNS ゾーン転送の設定不備による情報流出の危険性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160003.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160003.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB16-02) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160004.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160004.html",
		Title: `2016年1月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160005.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160005.html",
		Title: `2016年1月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160006.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160006.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2015-8704) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160007.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160007.html",
		Title: `2016年2月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160008.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160008.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-04) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160009.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160009.html",
		Title: `glibc ライブラリの脆弱性 (CVE-2015-7547) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160010.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160010.html",
		Title: `OpenSSL の複数の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160011.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160011.html",
		Title: `2016年3月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160012.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160012.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB16-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160013.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160013.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2016-1286) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160014.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160014.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-08) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160015.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160015.html",
		Title: `Oracle Java SE の脆弱性 (CVE-2016-0636) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160016.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160016.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-10) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160017.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160017.html",
		Title: `2016年4月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160018.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160018.html",
		Title: `2016年4月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160019.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160019.html",
		Title: `ケータイキット for Movable Type の脆弱性 (CVE-2016-1204) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160020.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160020.html",
		Title: `Apache Struts 2 の脆弱性 (S2-032) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160021.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160021.html",
		Title: `ImageMagick の脆弱性 (CVE-2016-3714) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160022.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160022.html",
		Title: `2016年 5月 Microsoft セキュリティ情報 (緊急 8件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160023.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160023.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB16-14) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160024.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160024.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-15) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160025.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160025.html",
		Title: `2016年 6月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160026.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160026.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-18) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160027.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160027.html",
		Title: `Apache Struts 2 の脆弱性 (S2-037) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160028.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160028.html",
		Title: `2016年 7月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160029.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160029.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-25) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160030.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160030.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB16-26) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160031.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160031.html",
		Title: `CGI 等を利用する Web サーバの脆弱性 (CVE-2016-5385 等) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160032.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160032.html",
		Title: `2016年7月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160033.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160033.html",
		Title: `2016年 8月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160034.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160034.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-29) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160035.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160035.html",
		Title: `2016年 9月 Microsoft セキュリティ情報 (緊急 7件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160036.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160036.html",
		Title: `Web サイトで使用されるソフトウエアの脆弱性を悪用した攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160037.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160037.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2016-2776) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160038.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160038.html",
		Title: `OpenSSL の脆弱性 (CVE-2016-6309) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160039.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160039.html",
		Title: `2016年 10月 Microsoft セキュリティ情報 (緊急 5件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160040.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160040.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-32) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160041.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160041.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB16-33) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160042.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160042.html",
		Title: `2016年10月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160043.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160043.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-36) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160044.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160044.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2016-8864) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160045.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160045.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-37) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160046.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160046.html",
		Title: `2016年 11月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160047.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160047.html",
		Title: `Web サイト改ざんに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160048.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160048.html",
		Title: `Adobe Flash Player の脆弱性 (APSB16-39) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160049.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160049.html",
		Title: `2016年 12月 Microsoft セキュリティ情報 (緊急 6件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160050.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160050.html",
		Title: `インターネットに接続された機器の管理に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2016/at160051.html": {
		URL:   "https://www.jpcert.or.jp/at/2016/at160051.html",
		Title: `SKYSEA Client View の脆弱性 (CVE-2016-7836) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170001.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170001.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB17-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170002.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170002.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-02) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170003.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170003.html",
		Title: `2017年 1月 Microsoft セキュリティ情報 (緊急 1件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170004.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170004.html",
		Title: `ISC BIND 9 に対する複数の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170005.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170005.html",
		Title: `2017年 1月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170006.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170006.html",
		Title: `WordPress の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170007.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170007.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2017-3135) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170008.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170008.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-04) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170009.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170009.html",
		Title: `Apache Struts 2 の脆弱性 (S2-045) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170010.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170010.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-07) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170011.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170011.html",
		Title: `2017年 3月 Microsoft セキュリティ情報 (緊急 9件含) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170012.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170012.html",
		Title: `USB ストレージに保存されたデータを窃取するサイバー攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170013.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170013.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-10) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170014.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170014.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB17-11) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170015.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170015.html",
		Title: `2017年 4月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170016.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170016.html",
		Title: `ISC BIND 9 に対する複数の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170017.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170017.html",
		Title: `2017年 4月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170018.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170018.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-15) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170019.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170019.html",
		Title: `2017年 5月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170020.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170020.html",
		Title: `ランサムウエア "WannaCrypt" に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170021.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170021.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-17) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170022.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170022.html",
		Title: `2017年 6月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170023.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170023.html",
		Title: `インターネット経由の攻撃を受ける可能性のある PC やサーバに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170024.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170024.html",
		Title: `ISC BIND 9 の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170025.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170025.html",
		Title: `Apache Struts 2 の脆弱性 (S2-048) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170026.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170026.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-21) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170027.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170027.html",
		Title: `2017年 7月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170028.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170028.html",
		Title: `Cisco WebEx Browser Extension の脆弱性 (CVE-2017-6753) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170029.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170029.html",
		Title: `2017年 7月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170030.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170030.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-23) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170031.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170031.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB17-24) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170032.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170032.html",
		Title: `2017年 8月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170033.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170033.html",
		Title: `Apache Struts 2 の脆弱性 (S2-052) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170034.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170034.html",
		Title: `NTTドコモ Wi-Fi STATION L-02F の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170035.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170035.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-28) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170036.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170036.html",
		Title: `2017年 9月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170037.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170037.html",
		Title: `Bluetooth の実装における脆弱性 "BlueBorne" に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170038.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170038.html",
		Title: `Apache Tomcat における脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170039.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170039.html",
		Title: `2017年 10月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170040.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170040.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-32) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170041.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170041.html",
		Title: `2017年 10月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170042.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170042.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-33) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170043.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170043.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB17-36) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170044.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170044.html",
		Title: `2017年 11月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170045.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170045.html",
		Title: `macOS High Sierra の設定に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170046.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170046.html",
		Title: `Microsoft Malware Protection Engine のリモートでコードが実行される脆弱性（CVE-2017-11937）に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170047.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170047.html",
		Title: `Adobe Flash Player の脆弱性 (APSB17-42) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170048.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170048.html",
		Title: `2017年 12月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2017/at170049.html": {
		URL:   "https://www.jpcert.or.jp/at/2017/at170049.html",
		Title: `Mirai 亜種の感染活動に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180001.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180001.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-01) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180002.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180002.html",
		Title: `2018年 1月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180003.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180003.html",
		Title: `2018年 1月 Oracle Java SE のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180004.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180004.html",
		Title: `Oracle WebLogic Server の脆弱性 (CVE-2017-10271) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180005.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180005.html",
		Title: `ISC BIND 9 の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180006.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180006.html",
		Title: `Adobe Flash Player の未修正の脆弱性 (CVE-2018-4878) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180007.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180007.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB18-02) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180008.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180008.html",
		Title: `2018年 2月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180009.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180009.html",
		Title: `memcached のアクセス制御に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180010.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180010.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-05) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180011.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180011.html",
		Title: `2018年 3月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180012.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180012.html",
		Title: `Drupal の脆弱性 (CVE-2018-7600) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180013.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180013.html",
		Title: `Cisco Smart Install Client を悪用する攻撃に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180014.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180014.html",
		Title: `Spring Framework の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180015.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180015.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-08) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180016.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180016.html",
		Title: `2018年 4月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180017.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180017.html",
		Title: `Spring Data Commons の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180018.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180018.html",
		Title: `2018年 4月 Oracle 製品のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180019.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180019.html",
		Title: `Drupal の脆弱性 (CVE-2018-7602) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180020.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180020.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-16) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180021.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180021.html",
		Title: `2018年 5月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180022.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180022.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB18-09) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180023.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180023.html",
		Title: `メールクライアントにおける OpenPGP および S/MIME のメッセージの取り扱いに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180024.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180024.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-19) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180025.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180025.html",
		Title: `2018年 6月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180026.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180026.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB18-21) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180027.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180027.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-24) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180028.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180028.html",
		Title: `2018年 7月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180029.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180029.html",
		Title: `2018年 7月 Oracle 製品のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180030.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180030.html",
		Title: `Apache Tomcat における複数の脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180031.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180031.html",
		Title: `ISC BIND 9 サービス運用妨害の脆弱性 (CVE-2018-5740) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180032.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180032.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB18-29) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180033.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180033.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-25) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180034.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180034.html",
		Title: `2018年 8月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180035.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180035.html",
		Title: `Ghostscript の -dSAFER オプションの脆弱性に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180036.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180036.html",
		Title: `Apache Struts 2 の脆弱性 (S2-057) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180037.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180037.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-31) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180038.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180038.html",
		Title: `2018年 9月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180039.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180039.html",
		Title: `Adobe Reader および Acrobat の脆弱性 (APSB18-34) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180040.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180040.html",
		Title: `Adobe Acrobat および Reader の脆弱性 (APSB18-30) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180041.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180041.html",
		Title: `2018年10月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180042.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180042.html",
		Title: `2018年10月 Oracle 製品のクリティカルパッチアップデートに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180043.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180043.html",
		Title: `Cisco Webex Meetings Desktop App および Cisco Webex Productivity Tools の脆弱性 (CVE-2018-15442) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180044.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180044.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-39) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180045.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180045.html",
		Title: `Adobe Acrobat および Reader の脆弱性 (APSB18-40) に関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180046.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180046.html",
		Title: `2018年11月マイクロソフトセキュリティ更新プログラムに関する注意喚起`,
		Team:  "jp",
	},
	"https://www.jpcert.or.jp/at/2018/at180047.html": {
		URL:   "https://www.jpcert.or.jp/at/2018/at180047.html",
		Title: `Adobe Flash Player の脆弱性 (APSB18-44) に関する注意喚起`,
		Team:  "jp",
	},
}
