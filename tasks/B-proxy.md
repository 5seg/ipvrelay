# タスクB: internal/proxy の実装

`internal/proxy/proxy.go` のスタブを実装せよ。他パッケージは触るな。

## 実装するもの
- `(*Server).Serve(ctx) error`
- SOCKS5 (RFC 1928) の CONNECT のみ対応
- 同一ポートで HTTP CONNECT も受け付ける(自動判別)

## 要件
1. 最初の1バイトで判別する: `0x05` なら SOCKS5、`'C'` なら HTTP CONNECT。
   先頭バイトを消費してしまうので、判別後は `io.MultiReader` などで戻すこと。
2. SOCKS5:
   - greeting: version=5。メソッドを読み、`05 00`(no auth) を返す。
   - request: CMD=1(CONNECT) のみ許可。BIND/UDP ASSOCIATE は `07`(command not supported) で拒否。
   - ATYP: 1=IPv4, 3=domain, 4=IPv6。**domain はそのまま Dial に渡す(ローカル解決禁止)。**
   - reply: `05 00 00 01 00 00 00 00 00 00`。失敗時は適切な REP コード
     (0x01 general, 0x03 network unreachable, 0x05 connection refused, 0x08 address type not supported)。
   - IPv6/BND.ADDR はとりあえずゼロ埋めで良い。
3. HTTP CONNECT: `CONNECT host:port HTTP/1.1` を解析。成功なら `HTTP/1.1 200 Connection Established\r\n\r\n`。
   失敗なら 502。ヘッダは CRLFCRLF まで読み捨てる。
4. 双方向コピー。half-close を正しく扱い(`CloseWrite` 相当)、`io.Copy` の戻りでカウンタを更新する。
   `net.TCPConn` 以外もあり得るので `interface{ CloseWrite() error }` の型アサーションで。
5. ハンドシェイクには `handshakeTimeout` を適用する。その後のコピーは ctx のキャンセルまで続ける。
6. Stats のカウンタ: active/total/failed/up/down を正しく増減する。
7. ctx がキャンセルされたら accept ループを抜け、開いている接続も閉じる。
8. ログは `s.logf` 経由。1接続1行程度(host:port と成否)。
9. 同時接続に耐えること。goroutine リークを残さない。

## 検証
自分の手元で `nc` や python の簡易サーバーを立て、SOCKS5 と HTTP CONNECT の
両方で疎通を確認せよ。`curl --proxy socks5h://127.0.0.1:PORT http://...` が通ること。
