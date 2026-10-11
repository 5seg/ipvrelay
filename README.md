# ipvrelay

IPVanish の WireGuard サーバーを TUI で切り替えられる、ローカル用 SOCKS5 プロキシ。
単一バイナリ、root 不要で動く。

## 何をするもの

`127.0.0.1` に SOCKS5 プロキシを立て、その出口を IPVanish の 3,599 サーバー
(112カ国 / 150都市)から選べる。出口は WireGuard トンネルなので、選んだサーバーの
IP から外に出ていく。

```
ブラウザ / curl / git / npm  ──SOCKS5──▶  ipvrelay  ──WireGuard──▶  IPVanish の出口
```

## 必要なもの

- Go 1.26 以降(ビルド時)
- IPVanish のアカウント
- Linux。カーネル権限は任意(無くても動く)

## ビルド

```sh
go build -ldflags="-s -w" -o ipvrelay ./cmd/ipvrelay
```

## 使い方

```sh
./ipvrelay
```

初回だけメールアドレスとパスワードを聞かれる。パスワードは保存されず、
交換したトークンだけが `~/.local/state/ipvrelay/state.json`(0600)に置かれる。
以後はトークンで自動的に再開し、失効したら自動更新する。
パスワードを聞き直すのはリフレッシュトークンまで切れたときだけ。

起動すると `127.0.0.1:1080` で SOCKS5 が待ち受ける。

```sh
export ALL_PROXY=socks5h://127.0.0.1:1080        # curl git npm pip go など
curl --proxy socks5h://127.0.0.1:1080 https://example.com
chromium --proxy-server="socks5://127.0.0.1:1080"
```

`socks5h` を使うこと。`socks5` だとホスト名が手元で解決され、DNS が漏れる。

### キー操作

| キー | 動作 |
|---|---|
| `↑` `↓` / `j` `k` | 移動 |
| `Enter` | 選択中のサーバーへ切り替え |
| `/` | 検索(国・都市・ホスト名) |
| `r` | RAM-only のみ表示 |
| `s` | ソート切り替え(RTT / 負荷 / 国) |
| `q` | 終了 |

### オプション

```
--listen 127.0.0.1:1080   待ち受けアドレス
--backend kernel|userspace|auto   auto が既定。特権があれば kernel
--iface  wg0              kernel バックエンドのインターフェース名
--email  you@example.com  アカウントのメール
--no-tui                  TUI を出さずログだけ
-v                        詳細ログ
```

## 仕組み

- **出口**: IPVanish のアプリ用 API (`api.ipvanish.com/api/v3`) からサーバー一覧と
  WireGuard の割り当てを取る。鍵ペアはローカルで生成し、公開鍵だけを送る。
- **トンネル**: 2方式を実行時に選ぶ。
  - `kernel` — カーネルの WireGuard モジュール。`ip rule` のソースルーティングで
    メインのルーティングテーブルには触らない。
  - `userspace` — wireguard-go + gVisor netstack。TUN デバイスも特権も要らない。
    カーネルが使えない環境ではこちらに落ちる。
- **RAM-only バッジ**: API の `features` ビットマスク(4 = RAM-only)をそのまま使う。
  サーバー単位で正確。
- **失効対策**: 割り当ては時間が経つと通らなくなる。30秒ごとにトンネルの疎通を見て、
  2回続けて失敗したら同じサーバーで割り当てを取り直す。

## 注意

- `1080` が他のプロセスに使われている場合は `--listen` で変える。
- ローカル区間(アプリ ↔ ipvrelay)はループバックなので暗号化していない。
  待ち受けは既定で `127.0.0.1` のみ。LAN に開けないこと。
- ポータル/アプリの非公開 API を使っている。仕様が変われば壊れる。
  `DESIGN.md` に調査記録と逃げ道を残してある。

## 構成

```
cmd/ipvrelay      エントリポイント
internal/vpnapi   IPVanish の v3 API クライアント
internal/backend  WireGuard トンネル(kernel / userspace)
internal/relay    認証・サーバー一覧・RTT 測定・切り替え・死活監視
internal/proxy    SOCKS5 + HTTP CONNECT
internal/tui      TUI
internal/config   トークンの保存
```
