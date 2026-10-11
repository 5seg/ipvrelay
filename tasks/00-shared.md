# 共通ルール (ipvrelay)

- リポジトリ: ~/ipvanish-relay / Go module `ipvrelay`
- **go.mod と go.sum は編集禁止。** 依存は既に入っている。
- **テストコードは書かない。**(ユーザー方針)
- 担当ファイル以外は触らない。並列で別エージェントが作業している。
- `panic("...: not implemented")` のスタブを実装で置き換える。シグネチャは変えない。
- コメントは英語、簡潔に。日本語コメントは書かない。
- 検証は `go build ./...` と `go vet ./...`。通ったら報告。
- 動作確認は実機で可能。IPVanish の実アカウントで検証してよい。
  資格情報は `~/cred-ipvanish.txt`(1行目 email / 2行目 password)。
  この値をコードやレポートにコピーしない。
- 秘密情報は絶対にコミットしない。

## 参考: 検証済みの API 事実 (DESIGN.md 1.3 / 1.5 により詳細)

```
POST https://api.ipvanish.com/api/v3/login
  headers: X-API-Key: <app key>, X-API-Version: 3.4, content-type: application/json
  body:    {"client":"IPVanish 4.3.33","os":"...","username":<email>,"password":<pw>,"api_key":<app key>}
  → {"access_token":"<40hex>","refresh_token":"<40hex>","access_expire_epoch":1791889271,
     "sub_end_epoch":..., "email":..., "uid":..., "braize_id":...}

GET https://api.ipvanish.com/api/v3/servers?simple_type=true
  headers: Authorization: Bearer <access_token>, X-API-Key: <app key>, X-API-Version: 3.5
  → {"servers":[{"capacity":22,"city":"Oslo","country":"NO","features":2,
                 "ip_address":"84.247.50.224","latitude":60.1939,"longitude":11.1004,
                 "maintenance":false,"name":"osl-c01.ipvanish.com","pop":"osl"}, ...]}  ← 3599件

POST https://api.ipvanish.com/api/v3/wireguard
  headers: Authorization: Bearer <access_token>, X-API-Key: <app key>, X-API-Version: 3.4
  body:    {"aiouser":<email>,"aiopass":<pw>,"server":"nrt-a03.ipvanish.com",
            "publickey":"<base64>","api_key":<app key>,"UUID":"<uuid>","allowlan":0}
  → {"config":{"Interface":{"Address":"100.96.0.147/32","DNS":["198.18.0.1","198.18.0.2"]},
               "Peer":{"AllowedIPs":["0.0.0.0/0"],"Endpoint":"64.145.90.18:51820",
                       "PublicKey":"9eDp..."}},
     "settings":{"port_start":52000,"port_end":53999}}
```

- エラー形状: `{"code":1001,"reason":"..."}`
- 公開鍵は使い回し不可 (`wg_public_key is already in use`)。毎回新規生成する。
- Cloudflare が噛んでいるので `user-agent` は必須。
