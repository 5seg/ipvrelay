# ipvanish-relay 設計メモ

TUI で接続先サーバーを切り替えられる、軽量な SOCKS5 プロキシ。
出口は IPVanish の WireGuard サーバー。ローカルクライアントは特別な設定なしに
`socks5h://127.0.0.1:1080` を向けるだけで使える。

## 1. 検証済みの事実

すべて実機で確認済み(2026-10-11)。

### 1.1 サーバー一覧 API(認証不要)

```
GET https://account.ipvanish.com/api-v4/server?country=JP
→ 3,599台 / 112カ国 / 150都市
   {"hostname":"nrt-a03.ipvanish.com","city":"Tokyo","countryCode":"JP",
    "country":"Japan","status":1,"capacity":17}
```

`capacity` は 3〜86(平均17.4)。負荷指標として TUI のソートに使える。
クエリ文字列を付けると全件、付けないと一部(632台/30都市)が返る挙動を確認済み。
`?country=JP` は絞り込みにならない(全件が返る)ので、常にこの形で取得する。

configs.zip(`https://configs.ipvanish.com/configs/configs.zip`)も同じ3,599台を
返すが、こちらは負荷情報が無くファイル名パースが要る。API を主、configs.zip を保険とする。
SOCKS5 の正規リストは `GET /api-v4/server/list/socks5`(18拠点、これも認証不要)。

### 1.2 認証(AWS Cognito、カスタムドメイン経由)

```
POST https://idp.sso.ipvanish.com/
content-type: application/x-amz-json-1.1
x-amz-target: AWSCognitoIdentityProviderService.InitiateAuth

{"AuthFlow":"USER_PASSWORD_AUTH",
 "ClientId":"4ec6gq3ktcm5g5f2p134ot7qi2",
 "AuthParameters":{"USERNAME":"<email>","PASSWORD":"<password>"}}
→ AuthenticationResult.{IdToken, AccessToken, RefreshToken}
```

- プール `us-east-1_lTh9X4Td9`。標準エンドポイント(`cognito-idp.us-east-1.amazonaws.com`)は
  `ForbiddenException: I'm a teapot` を返すので**必ずカスタムドメインを使う**。
- Cloudflare の bot 判定があるため、ブラウザ相当の `user-agent` が無いと 403 になる。
  `x-amz-user-agent: aws-amplify/6.6.0 js`、`origin`/`referer: https://sso.ipvanish.com/` を付ける。
- IdToken の有効期限は1時間。`REFRESH_TOKEN_AUTH` で更新できる(動作確認済み)。

### 1.3 WireGuard config の生成

**主経路は v3(1.5 参照)。鍵ペアをローカルで生成し、公開鍵だけを送る。**

```
POST https://api.ipvanish.com/api/v3/wireguard
Authorization: Bearer <access_token>, X-API-Key: <key>, X-API-Version: 3.4

{"aiouser":"<email>","aiopass":"<pass>","server":"nrt-a03.ipvanish.com",
 "publickey":"<我々が生成した公開鍵>","api_key":"<key>","UUID":"<任意のUUID>","allowlan":0}

→ {"config":{"Interface":{"Address":"100.96.0.147/32","DNS":["198.18.0.1","198.18.0.2"]},
             "Peer":{"AllowedIPs":["0.0.0.0/0"],"Endpoint":"64.145.90.18:51820",
                     "PublicKey":"9eDp…"}},
   "settings":{"port_start":52000,"port_end":53999}}
```

この構成で実際に接続し、出口が Tokyo `64.145.90.19` になることを確認済み。
秘密鍵はマシン外に出ない。

- **公開鍵は使い回せない。** 登録済みの鍵で再要求すると
  `wg_public_key is already in use` を返す。生成のたびに新鍵を作る。
  そのため生成した config(秘密鍵含む)はローカルにキャッシュして再利用する。
- キャッシュはサーバー単位。無駄な生成は IPVanish 側のクライアント登録を増やす。
- 取得に 1.3〜1.6秒。並列生成は可能。
- 保険として v4 経路もある(1.3b)。v4 はサーバー側で鍵を作るので手順は楽だが、
  Cognito ログインが Cloudflare 越しで壊れやすい。

### 1.3b v4 経路(保険)

```
POST https://account.ipvanish.com/api-v4/wireguard/config
Authorization: Bearer <Cognito IdToken>
{"server":"nrt-a34.ipvanish.com"}
→ [Interface] PrivateKey / Address / DNS と [Peer] PublicKey / AllowedIPs / Endpoint が丸ごと返る
```

- サーバーごとに鍵が違うので、切り替えは「config 取得 → デバイス再構成」。
- 再生成すると別の鍵とアドレスが返る。生成済み config は再利用できる。
- 存在しない FQDN は `No server with FQDN "..."` で弾かれる。
- **POST 専用**。GET は `/login` に 302 する。

### 1.4 トンネルの実装方式(両方実証済み)

| | userspace + netstack | カーネル WireGuard |
|---|---|---|
| 権限 | **不要** | root または CAP_NET_ADMIN |
| TUN デバイス | 不要(全てプロセス内) | 必要 |
| バイナリ | 13.6MB | より小さい(wgctrl + netlink のみ) |
| 速度(実測) | 7.2〜7.6 MB/s | 8.1〜8.3 MB/s |
| 参考: 素の回線 | 10.4 MB/s | 同左 |
| 東京サーバー経由 | 未測定 | 9.7 MB/s |

回線が 84Mbps で飽和するため差は約10%。上りの速い環境ではカーネル側が有利になる。
カーネル WG は `modprobe wireguard` で有効化でき、`ip rule from <tun IP> lookup <table>` の
ソースルーティングでメインのルーティングテーブルを一切触らずに済む(検証済み)。
これによりフルトンネルにせず、SOCKS5 で選択的にトンネルへ流せる。

### 1.5 v3 API(アプリ用)と `features` ビットマスク

アプリ(Windows/macOS/モバイル)は別系統の API を使っている。公式アプリを逆コンパイルして
契約を確定させた。

```
POST https://api.ipvanish.com/api/v3/login
X-API-Key: <app api key>
X-API-Version: 3.4
{"client":"IPVanish 4.3.33","os":"...","username":"<email>","password":"<pass>","api_key":"<key>"}
→ access_token / refresh_token / access_expire_epoch / sub_end_epoch / uid

GET https://api.ipvanish.com/api/v3/servers?simple_type=true
Authorization: Bearer <access_token>
X-API-Version: 3.5
→ 3,599台 {"name":"osl-c01.ipvanish.com","city":"Oslo","country":"NO","features":2,
          "capacity":22,"ip_address":"84.247.50.224","latitude":...,"longitude":...,
          "maintenance":false,"pop":"osl"}
```

API キーはアプリ本体(`IPVanish.exe`, .NET 単一ファイルバンドル)に定数として埋まっている。
`X-API-Version: 3.4` とボディの `api_key` の両方が必要。片方だけだと `API Key Invalid` になる。

**`features` のデコード**(`VpnSDK.Common.Enums.ServerFeature`):

| 値 | 意味 | 台数 |
|---|---|---|
| 1 | Virtual(物理サーバーを置かない仮想拠点) | 201 |
| 2 | StandardProtocolSet | 1,595 |
| **4** | **RamOnlyServer** | **1,251** |
| 8 | QuantumEncryption(耐量子暗号) | 0 |
| 16 | IPv6 | 1,231 |

### 1.6 RAM-only の正確な分布

**Web のマーケティングページの都市単位バッジは不正確だった。**
`https://www.ipvanish.com/servers/` は Salt Lake City を RAM-only と表示するが、
API の実データは `features=1`(Virtual のみ、非 RAM)で、RAM ではない。
正確な値は 1.5 の `features & 4` だけが持つ。

- 3,599台中 **1,251台** が RAM-only。32都市に分布。
- 都市全体が RAM-only: Madrid, Athens, Amsterdam, Kansas City, Edinburgh, Glasgow,
  Detroit, Buffalo, Seattle, Tirana, Tallinn, Ljubljana, Phoenix(13都市)。
- 混在: London 140/145、Ashburn 121/154、Frankfurt 91/120、Atlanta 118/235、
  New York 59/195、Tokyo 13/59、Chicago 14/109 など。

したがってバッジはサーバー単位で持ち、都市単位の集計はしない。

### 1.7 運用上わかったこと(実装に効く)

- **割り当ては失効する。** 生成から40分ほど放置した config は、ハンドシェイクは成功するのに
  データが一切通らなくなった。生成直後の config は 300ms で同じサーバーに通る。
  → config はキャッシュせず切り替えのたびに生成し、さらに死活監視で自動再取得する。
- **設定直後の一発目は落ちる。** handshake 完了前に最初のパケットを送ると丢棄され、
  特に DNS が丸ごとタイムアウトする。→ トンネル経由の TCP 接続が通るまで待ってから使う。
- **ICMP は非特権でも打てる。** Linux の ping socket (`SOCK_DGRAM` + `IPPROTO_ICMP`) を
  使えば `CAP_NET_RAW` 不要。`net.ipv4.ping_group_range` が範囲外なら raw socket か
  RTT 測定無しに落とす。RTT はこれで測る。
- **UDP 51820 への TCP 接続は無反応。** RTT 測定には使えない(timeout するだけ)。
- API のサーバー一覧は 3,433〜3,599 台の間で揺れる。固定値を前提にしない。

## 2. アーキテクチャ

```
ipvrelay (単一バイナリ)
├─ auth      v3 を主、v4 を保険。初回に email/password → トークンを 0600 で保存し、
│            失効したら自動 refresh。パスワードは保存しない。
├─ servers   v3 `/servers?simple_type=true` を定期取得。features から RAM/Virtual/IPv6/量子を
│            ビットで持ち、capacity と合わせてキャッシュ。v4 は features が無いので使わない。
├─ certs     カーネル WG が使えるか実行時に判定し、使えなければ userspace netstack に落とす。
├─ wg        鍵ペアはローカル生成。config はサーバー単位でキャッシュし、再生成を避ける。
├─ ingress   127.0.0.1:1080 SOCKS5。1バイト目で HTTP CONNECT も自動判別。
│            宛先ホスト名は解決せず上流に渡す(リーク防止)。
└─ tui       国/都市で絞り込み、負荷と RTT 表示、RAM/Virtual/IPv6 バッジ、出口IPと統計。
```

認証は v3 を主、v4 を保険とする。サーバー一覧は v3 のみが `features` を持つ。
バッジの対象は **サーバー単位** で、都市単位の集計はしない(1.6 のとおり Web の見た目は不正確)。

切り替えの実測コスト: config 生成 1.3〜1.6秒 + 再構成 0.01秒 + ハンドシェイク 0.3秒
= **おおむね1.5〜2秒**。事前に config を温めておけばさらに短縮できる。

## 3. 決定事項

1. **バックエンド**: euid==0 かつ wireguard モジュールが使えればカーネル、無ければ userspace
   netstack に自動フォールバック。`--backend` で上書き可。TUI にどちらを使ったかを表示する。
2. **資格情報**: 初回だけ email/password を聞き、トークンを 0600 の状態ファイルに保存。
   失効したらそこから自動 refresh。パスワードは保存しない。
3. **切替時の既存コネクション**: 旧トンネルを張ったまま新規接続だけ新ピアに流し、
   旧側が捌けるまで待つ(二重トンネル方式)。切替中も通信を切らさない。
4. **RAM バッジ**: v3 の `features` ビットでサーバー単位に判定(1.5/1.6)。
   都市単位の集計や Web スクレイプはしない。
5. **名称**: `ipvrelay`。
6. **待ち受け**: 127.0.0.1:1080 のみ。LAN 公開はしない。

## 3b. 実装前に掘り切るもの

- v3 の `features` に現在値 8(QuantumEncryption)が存在しない。将来用にビットは保持する。
- TUI に出す項目の最終確定(案: 国/都市/コード、負荷、RTT、RAM/Virtual/IPv6 バッジ、
  現在の出口IP、接続数、転送量)。
- config キャッシュの保存形式と TTL(再生成がいつまで有効かの実測)。

## 4. リスク

- **アプリ用 API キーの埋め込み**: v3 API はアプリに同梱の固定キーを要求する。アプリ更新で
  変われば壊れるので、定数として外出ししユーザーが差し替えられるようにする。
  逃げ道は v4 の Cognito 経路(features は失う)と configs.zip の OpenVPN 3,599件。
- **公開鍵の使い回し禁止**: v3 は同一公開鍵での再生成を拒む。鍵をキャッシュしないと
  切り替えのたびに登録クライアントが増える。
- **非公開 API 依存**: `/api-v3/*` `/api-v4/*` は文書化されていない。変更されたら壊れる。
- **Cloudflare**: ヘッダ次第で 403。ログイン失敗時は明確なエラーを出す。
- **config 生成の乱発**: 1回ごとに鍵とアドレスが増える。キャッシュを必須にする。
- **SOCKS5 は暗号化しない**: 出口が VPN でも、ローカル区間はループバックなので実害はないが、
  待ち受けを LAN に開放する場合は要検討。既定は loopback のみ。

## 5. 実装状況 (2026-10-11)

完成。`cmd/ipvrelay` + `internal/{vpnapi,backend,relay,proxy,tui,config}`、約3,200行。
`go build ./...` と `go vet ./...` はクリーン、gofmt 済み。バイナリは 11.0 MB (stripped)。

実測値:

| 項目 | 結果 |
|---|---|
| 切り替え | 0.7〜2.5秒(生成+再構成+ハンドシェイク+疎通待ち) |
| SOCKS5 経由の速度 | 10.07 MB/s(直結 10.4 MB/s とほぼ同等) |
| 起動 | 3599台の取得と初回接続まで約2秒(トークン再利用時) |
| バックエンド | 非特権では userspace、root では kernel |
| HTTP CONNECT | 同一ポートで同時に動作 |

並列実装は herdr のタブ3枚に pi (gemini-3.8-flash low) を割り当て、
`internal/vpnapi` / `internal/proxy` / `internal/tui` を分担させた。
インターフェースを先に凍結してから投げたので衝突は起きていない。
tui は termios の調査に迷い込んで10分タイムアウトしたため誘導し、
それでも止まったので最終的には統合した(現在の `tui.go` はその成果物)。

未実装: `--print` なし、設定ファイルからの API キー差し替えは state の `api_token` のみ対応。
