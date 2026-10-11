# タスクA: internal/vpnapi の実装

`internal/vpnapi/vpnapi.go` のスタブを実装せよ。他パッケージは触るな。

## 実装するもの
- `(*Client).Login(ctx, username, password) (Tokens, error)`
- `(*Client).Refresh(ctx, refreshToken) (Tokens, error)`
- `(*Client).Servers(ctx) ([]Server, error)`
- `(*Client).WireGuardConfig(ctx, hostname, publicKey) (WireGuardConfig, error)`
- `(*Client).newRequest(...)` 内部ヘルパ

## 要件
1. リクエストには必ず `X-API-Key` と `X-API-Version`、`user-agent: IPVanish 4.3.33 (Windows)` を付ける。
2. `/login` のボディに `api_key` を必ず入れる。**ヘッダだけだと `API Key Invalid` になる。**
3. 認証後のリクエストは `Authorization: Bearer <accessToken>` を付ける。
4. HTTP ステータスが 2xx 以外、または `{"code":N,...}` が返ったら error にする。
   error には reason と code を含める。
5. login の `access_expire_epoch` (Unix秒) を `Tokens.ExpiresAt` に入れる。
   `Refresh` がその値を返さない場合は、既存の有効期限か now+1h を使う。
6. `/servers` は `{"servers":[...]}` の wrapper を剥がして返す。
   `LatencyMS` は -1 で初期化する(未測定)。
7. `/wireguard` は settings の `port_start`/`port_end` も `WireGuardConfig` に入れる。
   `AllowedIPs` と `DNSServers` はスライスで返す。
8. コンテキストを尊重する。タイムアウトは `c.http` のものを使う。
9. baseURL は `c.baseURL` を使う(ミラー差し替えのため)。パスの先頭 `/` の重複に注意。
10. 同時呼び出し安全にすること(トークンは起動後に書き換えない前提でよいが、
    読み取りは race しないように)。

## 検証
`~/cred-ipvanish.txt` を使い、一時的な main を別ディレクトリで書いて
Login → Servers(3599件) → WireGuardConfig が通ることを確認せよ。
確認したら一時ファイルは消せ。鍵生成は `golang.org/x/crypto/curve25519` で行う
(既に依存にある。32byteランダム → clamp → basepoint)。
