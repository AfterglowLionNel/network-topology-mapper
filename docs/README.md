# 詳しい使い方

Network Topology Mapper は、Windows PC のネットワーク状態を測定し、自分が管理する LAN の構成図と診断レポートを作ります。最初はローカル限定の基本診断から始めてください。

詳細調査は、自分が所有・管理する LAN、または明示的な許可を受けた範囲だけで実行してください。通常の `output/` は秘密情報として扱い、共有が必要な場合も `[P]` で作った仮名化版を目視確認して使用します。保存情報については [PRIVACY.md](../PRIVACY.md) を参照してください。

## 起動方法

エクスプローラーから `Run.vbs` または `Start.bat` をダブルクリックします。PowerShell 7 があれば優先して使い、なければ Windows PowerShell 5.1 で動作します。

PowerShell 7 の方が詳細 LAN 調査は高速です。導入案内を選んだ場合だけ winget または Microsoft のダウンロードページを使用します。

## メニュー

### [1] 基本診断

PC、ネットワークアダプター、既定ゲートウェイまでを約 10 秒で確認します。LAN 全探索、インターネット側の確認、速度測定は行いません。結果は `output/network-health.json` に保存します。

「今つながらない」「PC 側の設定をまず確認したい」ときの最初の選択です。

### [2] 詳細LAN調査

構成図、端末一覧、診断、AI修正依頼を含む `output/diagram.html` を作ります。

実行前に次を表示し、`y` を入力した場合だけ能動調査を始めます。

- 対象ネットワークの CIDR
- 対象 NIC と Windows のネットワーク種別
- 最大ホスト数
- 外部サービス通信の有無

対象は「プライベート」に設定された物理 NIC と RFC 1918 IPv4 `/22`〜`/30` に限定されます。合計 1,022 ホストを超える場合は停止します。

続けて、公開 IP、回線情報、IEEE OUI、初回の Mermaid 取得などの外部情報を使うか確認します。`N` なら LAN 内だけで続行します。速度測定は含まれません。

詳細調査の機器プローブには、ping、ARP/近隣表、SSDP/UPnP、mDNS、NetBIOS、HTTP バナー、代表ポート確認が含まれます。許可された自分の LAN 以外では実行しないでください。

### [V] インターネット速度測定

Cloudflare の測定用エンドポイントを使います。実行前に確認し、既定上限は次のとおりです。

- ダウンロード: 約 180 MB
- アップロード: 約 20 MB
- 合計: 約 200 MB

アップロードするのはツールが生成した測定用バイト列です。診断 JSON や端末一覧は送信しません。テザリングや従量制回線では通信量に注意してください。

### [3] モニタモード

既定ゲートウェイへ 1 秒間隔で ping し、遅延、損失、ジッター、スパイク、瞬断を記録します。既定は 60 秒です。インターネット側の監視を追加する場合だけ、別途 `8.8.8.8` への通信を確認します。

既存の詳細調査データがある場合、結果を統合レポートへ反映します。

### [F] 設定の不備を修正

直近の診断から、許可リストにある PC 側の修復候補だけを表示します。

- `[1]` は確認だけで、設定を変更しません。
- `[2]` は内容を再確認してから適用します。
- `[3]` は直前の変更をロールバックします。

ルーター設定、機器交換、回線契約などは自動変更しません。一部の Windows 設定では管理者権限の確認が表示されます。

### [S] 定期実行

Windows のタスクとして、基本診断または基本診断 + モニタを毎日実行します。登録内容は表示でき、不要になれば解除できます。

端末差分の履歴はネットワークごとに最大 30 件、診断値は最大 120 件です。

### [O] 前回の結果を開く

`output/diagram.html` を既定ブラウザで開きます。まだない場合は `[2]` を実行してください。

### [P] 公開用レポート

既存の詳細調査データから、次の別ファイルを生成します。

- `output/diagram-public.html`
- `output/diagram-public.mmd`
- `output/diagram-public.drawio`
- `output/devices-public.csv`
- `output/ai-repair-prompt-public.txt`

公開用では IP、MAC、PC名、ユーザー名、SSID、端末名などを一貫した仮名へ置き換え、履歴、プロセス、接続先、外部回線情報などを除外します。これは匿名化の保証ではないため、公開前に必ずファイルを目視確認してください。

### [H] ヘルプ / [L] 軽量モード

`[H]` は `docs/help.html` をブラウザで開きます。`[L]` は詳細調査時の NetBIOS / HTTP など時間のかかる機器特定を省きます。

## HTMLレポート

通常レポートには次のタブがあります。

- 概要: 主要な結果と要確認事項
- 構成図: LAN のトポロジ
- 診断: 各検査、推定原因、履歴
- AI修正依頼: すべての問題と実測値をまとめた AI 向けプロンプト
- 機器: 発見した端末と識別根拠
- 接続 / 経路など: 取得できた範囲の補足情報

AI修正依頼は読み取り専用欄に表示され、「コピー」ボタンで一括コピーできます。Clipboard API が使えないローカルファイル環境では、選択と `document.execCommand('copy')` にフォールバックします。コピー結果は画面上のステータスでも通知します。

問題が複数ある場合も別々のプロンプトにはせず、一つの依頼にまとめます。各診断の `metrics` とモニタ値が存在する場合は、`key=value` として実際の数値を含めます。問題がない場合は、その旨を記した TXT とページを生成します。

## CLIの例

リポジトリのルートで実行してください。

```powershell
# ローカル限定の基本診断
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1

# 確認付き詳細調査
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan

# 外部情報も含める詳細調査
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -ExternalChecks

# 機器特定を軽量化
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -Light

# 対象 NIC とホスト上限をさらに限定
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -ScanInterfaceIndex 12 -MaxScanHosts 254

# 非対話。対象範囲を事前に確認できた自動化だけで使用
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -ApproveActiveScan -NoOpen

# 外部確認付き基本診断
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DiagnoseOnly -ExternalChecks

# 外部通信を明示的に禁止
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DiagnoseOnly -NoExternalServices

# 速度測定の通信量を小さく指定
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DiagnoseOnly -SpeedTest -SpeedTestMaxMB 50 -SpeedTestUploadMB 5

# 5 分間のローカルモニタ
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -Monitor -MonitorDuration 300 -NoOpen

# 公開用ファイルを作り、自動では開かない
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -PublicReport -NoOpen
```

Windows PowerShell 5.1 の場合は、先頭の `pwsh` を `powershell.exe` に置き換えられます。

## 端末に名前を付ける

`config/known-devices.sample.json` を `config/known-devices.json` という名前でコピーして編集します。キーには MAC アドレスまたは IP アドレスを使えます。

```json
{
  "devices": {
    "00-00-5E-00-53-01": {
      "name": "リビングのテレビ",
      "note": "55インチ"
    },
    "192.168.10.20": {
      "name": "書斎のプリンタ",
      "note": "家族共用"
    }
  }
}
```

実際の MAC、IP、名称を含む `known-devices.json` は Git 管理から除外されます。公開用レポートでも自由記述が意図どおり仮名化されているか確認してください。

## 出力ファイル

主な通常出力は次のとおりです。

| ファイル | 内容 |
|---|---|
| `network-health.json` | 診断結果、実測値、推定原因 |
| `network-data.json` | NIC、IP、近隣端末、経路、機器情報 |
| `internet-info.json` | 明示的な外部確認で取得した公開 IP / ASN / RDAP / STUN 等 |
| `network-monitor.json` / `monitor.html` | 連続監視の結果 |
| `diagram.html` | 通常の統合レポート |
| `diagram.mmd` / `diagram.drawio` | 構成図の再利用用データ |
| `devices.csv` | 端末一覧 |
| `ai-repair-prompt.txt` | 実測値入りの統合 AI 修正依頼 |
| `history/` | 端末差分と診断値の履歴 |

これらはネットワークの秘密情報です。通常出力は Git、Issue、SNS、公開 AI チャットへ添付しないでください。

## トラブルシューティング

### 詳細調査が「安全に調査できるLANがありません」で止まる

Windows の「ネットワークとインターネット」で、信頼できる自宅 LAN のネットワークプロファイルが「プライベート」か確認してください。職場や公衆 Wi-Fi を回避するため、「パブリック」では詳細調査を許可しません。

VPN、仮想 NIC、Bluetooth、コンテナ、`/21` より広いネットワーク、RFC 1918 以外は自動対象外です。

### 構成図だけ表示されない

初回は Mermaid がまだない可能性があります。自分のネットワーク方針で許可できる場合、`[2]` の外部情報確認に `y` と答えると、固定版を取得して SHA-256 を検証します。取得できなくても、診断表や AI 修正依頼など他の内容は利用できます。

### 端末が少なく表示される

スリープ中の端末、クライアント分離された Wi-Fi、応答しないファイアウォール、ランダム MAC の端末は発見できない場合があります。結果は「応答した機器」であり、LAN 内の全機器を保証するものではありません。

### PowerShellの実行警告が出る

配布元とファイル内容を確認してください。GitHub 以外の再配布物は改変されている可能性があります。恒久的に実行ポリシーを緩める必要はありません。

### 修復後に戻したい

メニュー `[F]` → `[3] 直前の変更を元に戻す` を使います。AI の提案を別途実行した変更は本ツールのロールバック対象外です。

## プライバシーと外部通信

- [PRIVACY.md](../PRIVACY.md)
- [NETWORK_SERVICES.md](../NETWORK_SERVICES.md)
- [SECURITY.md](../SECURITY.md)

外部サービスへ接続した場合、相手には接続元の公開 IP と通常の通信メタデータが見えます。結果ファイルを本プロジェクトのサーバーへ自動送信する機能はありません。
