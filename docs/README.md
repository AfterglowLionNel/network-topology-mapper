# 詳しい使い方

Network Topology Mapper は、Windows PC のネットワーク状態を測定し、自分が管理する LAN の構成図と診断レポートを作ります。通常はメニューの `[1] フル実行` を選びます。

詳細調査は、自分が所有・管理する LAN、または明示的な許可を受けた範囲だけで実行してください。通常の `output/` は秘密情報として扱い、共有が必要な場合も `[2] その他の機能` → `[P]` で作った仮名化版を目視確認して使用します。保存情報については [PRIVACY.md](../PRIVACY.md) を参照してください。

## 起動方法

エクスプローラーから `Run.vbs` または `Start.bat` をダブルクリックします。PowerShell 7 があれば優先して使い、なければ Windows PowerShell 5.1 で動作します。

PowerShell 7 の方が詳細 LAN 調査は高速です。導入案内を選んだ場合だけ winget または Microsoft のダウンロードページを使用します。

## メニュー

### [1] フル実行

次を一括で実行します。

- PC、ネットワーク、DNS、HTTPS の診断
- Cloudflare を使った速度測定
- 既定ゲートウェイとインターネット側の60秒間の通信品質モニタ
- LAN 内の機器調査と機器特定
- 公開 IP、回線、メーカー情報の取得
- 構成図、診断、AI修正依頼を含む `output/diagram.html` の生成

開始前に対象 NIC、CIDR、最大ホスト数、外部通信、速度測定の通信量、通信品質の監視時間をまとめて表示します。内容を確認して `y` を入力した場合だけ開始し、完了後は HTML レポートを既定ブラウザで自動的に開きます。

調査対象は物理 NIC の RFC 1918 IPv4 `/22`〜`/30` に限定されます。Windows のネットワーク種別が「パブリック」の場合は警告を表示するため、自分が管理する LAN だと確認できる場合だけ続けてください。速度測定は下り約 180 MB、上り約 20 MB、合計約 200 MB が上限です。

### [2] その他の機能

使用頻度の低い機能は、この中にまとめています。

| キー | 内容 |
|---|---|
| `1` | PC、NIC、既定ゲートウェイまでの基本診断。LAN 全探索・外部通信なし |
| `2` | 外部通信と速度測定を行わず、LAN 構成図とレポートを生成 |
| `V` | Cloudflare を使う速度測定のみ実行。最大約 200 MB |
| `3` | 既定ゲートウェイの遅延、損失、ジッター、瞬断を監視 |
| `F` | PC 側の修復候補を確認、適用、またはロールバック |
| `S` | 基本診断やモニタの定期実行を設定 |
| `P` | 仮名化した公開用レポートを別名で生成 |
| `L` | 時間のかかる一部の機器特定を省く軽量モード |

基本診断の結果は `output/network-health.json` に保存します。モニタは既定で60秒間実行し、既存の調査データがあれば統合レポートへ反映します。

修復機能は許可リストにあるPC設定だけを対象とし、「見るだけ」「確認後に適用」「直前の変更を元に戻す」から選べます。ルーター設定、機器交換、回線契約は自動変更しません。

公開用レポートでは IP、MAC、PC名、ユーザー名、SSID、端末名などを一貫した仮名へ置き換えます。生成される `diagram-public.html`、`devices-public.csv`、`ai-repair-prompt-public.txt` などは、共有前に必ず目視確認してください。

### [O] 前回の結果 / [H] ヘルプ

`[O]` は `output/diagram.html` を開きます。`[H]` は使い方と結果の見方をまとめた `docs/help.html` を開きます。

## HTMLレポート

通常レポートには次のタブがあります。

- 構成図: LAN のトポロジ
- 診断: 各検査と推定原因
- AI修正依頼: すべての問題と実測値をまとめた AI 向けプロンプト
- 機器: 発見した端末と識別根拠
- 通信・回線: 回線情報、現在の通信量、接続先、経路、アダプタ
- モニタ: 遅延、損失、ジッター、瞬断のグラフ、下り・上り速度の現在値・履歴・実測表、診断値の推移

フル実行では「モニタ」まで自動測定します。速度は診断の根拠としても残し、見比べやすい表示をモニタ側にも追加しています。「診断値の推移」もモニタに表示します。履歴グラフは同じネットワークでの実行結果だけを使い、初回は現在値、2回目以降は推移も表示します。

AI修正依頼は読み取り専用欄に表示され、「コピー」ボタンで一括コピーできます。Clipboard API が使えないローカルファイル環境では、選択と `document.execCommand('copy')` にフォールバックします。コピー結果は画面上のステータスでも通知します。

問題が複数ある場合も別々のプロンプトにはせず、一つの依頼にまとめます。各診断の `metrics` とモニタ値が存在する場合は、`key=value` として実際の数値を含めます。問題がない場合は、その旨を記した TXT とページを生成します。

## CLIの例

リポジトリのルートで実行してください。

```powershell
# ローカル限定の基本診断
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1

# 確認付き詳細調査
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan

# 「パブリック」プロファイルの物理LANも確認候補に含める
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -AllowPublicProfile

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

# 詳細LAN調査に60秒モニタも含める
pwsh -NoProfile -File .\scripts\Run-NetworkMapper.ps1 -DetailedScan -ExternalChecks -SpeedTest -IncludeMonitor -MonitorDuration 60 -NoOpen

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

初回は Mermaid がまだない可能性があります。`[1] フル実行` では固定版を取得して SHA-256 を検証します。外部通信なしの LAN レポートを選んだ場合など、取得できないときも診断表や AI 修正依頼は利用できます。

### 端末が少なく表示される

スリープ中の端末、クライアント分離された Wi-Fi、応答しないファイアウォール、ランダム MAC の端末は発見できない場合があります。結果は「応答した機器」であり、LAN 内の全機器を保証するものではありません。

### PowerShellの実行警告が出る

配布元とファイル内容を確認してください。GitHub 以外の再配布物は改変されている可能性があります。恒久的に実行ポリシーを緩める必要はありません。

### 修復後に戻したい

メニュー `[2] その他の機能` → `[F]` → `[3] 直前の変更を元に戻す` を使います。AI の提案を別途実行した変更は本ツールのロールバック対象外です。

## プライバシーと外部通信

- [PRIVACY.md](../PRIVACY.md)
- [NETWORK_SERVICES.md](../NETWORK_SERVICES.md)
- [SECURITY.md](../SECURITY.md)

外部サービスへ接続した場合、相手には接続元の公開 IP と通常の通信メタデータが見えます。結果ファイルを本プロジェクトのサーバーへ自動送信する機能はありません。
