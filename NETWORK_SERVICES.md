# 外部通信先

基本診断は LAN 全探索も外部サービス通信も行いません。以下は、利用者が外部確認、速度測定、初回ライブラリ取得、テスト用依存関係の取得などを明示的に選んだ場合だけ使用します。

サービスの仕様や利用条件は提供者により変更されることがあります。組織のネットワークで使う場合は、その組織のポリシーも確認してください。

| 通信先 | 用途 | 送られる主な情報 | 有効になる条件 |
|---|---|---|---|
| Cloudflare / Google の公開 DNS IP（IPv4 / IPv6） | インターネット側の ping、MTU、traceroute | 接続元 IP と ICMP | 外部確認または外部モニタを選択 |
| 設定済み DNS リゾルバー | Google、Cloudflare、YouTube 等の名前解決時間 | 問い合わせ名 | 外部確認を選択 |
| Google、GitHub、YouTube | TCP 443 / HTTPS 到達性 | 接続元 IP、TLS/HTTP メタデータ | 外部確認を選択 |
| Google、Yahoo! JAPAN | TCP、TLS、HTTP 応答時間 | 接続元 IP、Host、User-Agent | 外部確認を選択 |
| `api.ipify.org`、`api64.ipify.org`、`api6.ipify.org` | 公開 IPv4 / IPv6 の確認 | 接続元 IP、HTTP メタデータ | 外部確認を選択 |
| Team Cymru DNS | 公開 IP に対応する ASN / ISP の照会 | 逆順にした公開 IP または ASN を含む DNS 名 | 外部確認を選択 |
| `rdap.org` | 公開 IP の RDAP 登録情報 | URL に含まれる公開 IP | 詳細調査で外部確認を選択 |
| `stun.cloudflare.com:3478` | 外部から見える UDP アドレスの確認 | STUN パケット、接続元 IP / ポート | 詳細調査で外部確認を選択 |
| `speed.cloudflare.com/__down` | ダウンロード速度測定 | 接続元 IP、要求バイト数、HTTP メタデータ | 速度測定を明示 |
| `speed.cloudflare.com/__up` | アップロード速度測定 | 接続元 IP、生成した測定用バイト列、HTTP メタデータ | 速度測定を明示 |
| `standards-oui.ieee.org` | IEEE OUI CSV / TXT の取得 | 接続元 IP、HTTP メタデータ。端末の MAC は送信しない | 詳細調査で外部確認を選択し、キャッシュがない場合 |
| `cdn.jsdelivr.net` | 固定版 Mermaid 11.16.0 の取得 | 接続元 IP、HTTP メタデータ | 外部ダウンロードを許可し、検証済みキャッシュがない場合 |
| PowerShell Gallery | 固定版 Pester 6.0.0 の取得 | 接続元 IP、PowerShellGet の通信メタデータ | 開発者がテストを実行し、Pester 6 がない場合 |
| Microsoft / winget | PowerShell 7 の案内・インストール | winget / Microsoft が定める通信情報 | 利用者がメニューからインストールを選択 |

Cloudflare の速度測定は既定で、下り約 180 MB、上り約 20 MB、合計約 200 MB を上限にします。測定結果を Cloudflare の結果登録 API へ投稿する処理はありません。

Mermaid は取得後に SHA-256 を照合し、一致したファイルだけを `output/lib/` に保存してレポートからローカル読込します。版とハッシュはソースコードに固定しています。

## 外部通信を止める

- 基本診断は追加指定なしで実行します。
- 詳細 LAN 調査の外部情報確認では `N` を選びます。
- 対応する CLI モードでは `-NoExternalServices` を指定します。
- 公開用レポート生成は外部ダウンロードを無効にして実行されます。

Windows や DNS キャッシュ、セキュリティ製品など、このツールの外側で発生する通信までは制御できません。
