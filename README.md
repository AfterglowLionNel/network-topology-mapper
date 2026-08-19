# Network Topology Mapper

Windows PC から、自分が管理する LAN の構成とネットワーク不調を調べ、読みやすい HTML レポートを作る PowerShell ツールです。

問題が見つかった場合は、測定した数値とすべての問題を一つにまとめた「AI修正依頼プロンプト」も生成します。プロンプトは TXT で保存され、HTML レポートからワンクリックでコピーできます。

詳細調査は、自分が管理するネットワーク、または明示的な許可を受けた範囲だけで実行してください。

## 安全な既定動作

- コマンドラインで引数なしの場合は、PC・NIC・既定ゲートウェイまでの基本診断だけを行います。LAN 全探索と外部サービス通信は行いません。
- LAN の能動調査は `-DetailedScan` を指定したときだけです。対象 CIDR と最大台数を表示し、既定は `N` の確認を求めます。
- 調査対象は、Windows で「プライベート」に設定された物理 NIC、RFC 1918 の IPv4 `/22`〜`/30`、合計最大 1,022 ホストに制限されます。
- 外部確認は `-ExternalChecks`、速度測定は `-SpeedTest` を明示したときだけです。
- `-NoExternalServices` を付けると、対応モードの外部サービス通信を強制的に止められます。
- 修復は許可済みの PC 設定だけを対象とし、実行前に内容を表示します。直前の変更はロールバックできます。

## 動作環境

- Windows 10 / 11
- Windows PowerShell 5.1、または PowerShell 7

PowerShell 7 を推奨します。5.1 でも動作しますが、詳細調査の機器プローブは直列実行になるため時間がかかります。

## 入手方法

GitHub の Releases または「Code」から ZIP を取得するか、次のコマンドでクローンします。

```powershell
git clone https://github.com/AfterglowLionNel/network-topology-mapper.git
```

## 使い始める

1. このリポジトリを ZIP で取得して展開します。
2. `Run.vbs` または `Start.bat` をダブルクリックします。
3. `[1] フル実行` を選びます。
4. 表示された対象 LAN と通信量を確認して `y` を入力します。完了すると HTML レポートが自動で開きます。

メニューの主な項目は次のとおりです。

| キー | 内容 |
|---|---|
| `1` | 診断、速度測定、LAN 調査、機器特定、HTML レポート生成を一括実行 |
| `2` | 基本診断、外部通信なしの LAN レポート、モニタ、修復などを開く |
| `O` | 前回の通常レポートを開く |
| `H` | ローカルのヘルプを開く |
| `Q` | 終了 |

フル実行では、対象 CIDR、最大ホスト数、外部通信、Cloudflare 速度測定の上限（下り約 180 MB + 上り約 20 MB）を開始前にまとめて表示します。

詳しい使い方は [docs/README.md](docs/README.md) にあります。

## コマンドライン

リポジトリのルートで実行します。

```powershell
# 基本診断。LAN 全探索・外部サービス通信なし
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1

# 対象範囲を表示し、確認後に詳細 LAN 調査
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan

# CI などの非対話実行。対象 LAN を事前確認した場合だけ使用
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -ApproveActiveScan -NoOpen

# 外部到達性・DNS・HTTPS も確認
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DiagnoseOnly -ExternalChecks

# 通信量上限付き速度測定
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DiagnoseOnly -SpeedTest

# 5 分間モニタし、ブラウザは開かない
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -Monitor -MonitorDuration 300 -NoOpen

# 既存の詳細調査結果から公開用レポートを生成
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -PublicReport -NoOpen
```

`-ApproveActiveScan` は、表示される CIDR が自分または組織から許可された範囲だと事前に確認できる自動化だけで使用してください。

## レポートとAI修正依頼

詳細 LAN 調査後に `output/diagram.html` が作られます。「AI修正依頼」タブには、次の内容を一つにまとめたプロンプトが表示されます。

- `warn` / `fail` になったすべての診断項目
- 推定原因と根拠
- ダウンロード速度、遅延、損失率、ジッターなど取得できた実測値
- 複数の問題を分割せず、まとめて調査・修正・再測定する指示
- 管理者権限、通信断、ルーター変更、課金、不可逆操作の前に利用者へ確認する指示

同じ内容は `output/ai-repair-prompt.txt` に保存されます。公開用は仮名化後の情報だけから `output/ai-repair-prompt-public.txt` を生成します。

診断文字列はプロンプト内で「参考データ」として区切り、そこに含まれる文章を命令として扱わないよう指示しています。ただし、AIへ送る前に内容を確認してください。

## 保存データと公開用レポート

通常の `output/` には IP アドレス、MAC アドレス、ホスト名、SSID、端末名、接続情報などが含まれ得ます。ディレクトリは Git 管理から除外されていますが、通常レポートをそのまま公開しないでください。

`[2] その他の機能` → `[P]` の公開用レポートは、IP・MAC・名称などを一貫した仮名へ置き換え、履歴、プロセス、接続先、外部回線情報などを除外します。これは「匿名化の保証」ではありません。珍しい構成、測定時刻、端末数、自由記述などから推測される可能性があるため、公開前に必ず目視確認してください。

詳しくは [PRIVACY.md](PRIVACY.md) と [NETWORK_SERVICES.md](NETWORK_SERVICES.md) を参照してください。

## 利用上の注意

能動調査は、自分が所有・管理するネットワーク、または明示的な許可を受けた範囲だけで実行してください。職場、学校、宿泊施設、公衆 Wi-Fi、他人のネットワークを無断で調査しないでください。

外部確認を有効にすると、接続先のサービスへ公開 IP など通常の通信情報が送られます。通信先と内容は [NETWORK_SERVICES.md](NETWORK_SERVICES.md) に記載しています。

本ツールは診断支援であり、結果、推定原因、特定目的への適合性を保証するものではありません。修復前の表示内容とロールバック方法を確認し、ルーター変更、通信断、課金、管理者権限、不可逆操作を伴う提案は利用者自身で判断してください。

## OSSへの参加

- バグ報告・変更提案: [CONTRIBUTING.md](CONTRIBUTING.md)
- 脆弱性の連絡: [SECURITY.md](SECURITY.md)
- 第三者ソフトウェア等: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

テストは次のコマンドで実行できます。Pester 6 が見つからない場合、固定版 6.0.0 をユーザー領域へ取得します。

```powershell
pwsh -NoProfile -File .\tests\Invoke-Tests.ps1
```

## ライセンス

このプロジェクトは [MIT License](LICENSE) で公開します。第三者の名称・商標は各権利者に帰属します。
