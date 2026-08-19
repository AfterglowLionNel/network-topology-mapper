# 第三者ソフトウェア等

このファイルは、Network Topology Mapper が利用または参照する主な第三者要素をまとめたものです。各ライセンス本文と提供者の条件が優先されます。

## 配布時または実行時に取得するソフトウェア

### Mermaid 11.16.0

- 用途: HTML レポートのネットワーク構成図
- ライセンス: MIT License
- 配布形態: 必要時に jsDelivr から固定版を取得し、SHA-256 を検証して `output/lib/` に保存
- ライセンス本文: [third_party/mermaid-LICENSE.txt](third_party/mermaid-LICENSE.txt)
- プロジェクト: <https://github.com/mermaid-js/mermaid>

### Pester 6.0.0 / 互換 6.x

- 用途: 開発・CI のテストのみ
- ライセンス: Apache License 2.0
- 配布形態: アプリ本体には同梱しない。必要時に PowerShell Gallery からユーザー領域へ取得
- プロジェクト: <https://github.com/pester/Pester>

### actions/checkout 6.1.0

- 用途: GitHub Actions のテスト用チェックアウト
- ライセンス: MIT License
- 配布形態: GitHub Actions 上で固定コミットを参照し、アプリ本体には同梱しない
- プロジェクト: <https://github.com/actions/checkout>

## データとサービス

### IEEE Registration Authority OUI データ

MAC アドレスから組織名を推定するため、利用者が外部取得を許可した場合に IEEE の公開リストを取得します。OUI データ本体はこのリポジトリへ同梱しません。データの著作権、利用条件、商標は IEEE および各権利者に帰属します。

### 外部測定サービス

Cloudflare、Google、GitHub、Yahoo! JAPAN、ipify、RDAP.org、Team Cymru 等は通信先として利用しますが、そのソフトウェアや商標を本プロジェクトが所有・配布するものではありません。詳細は [NETWORK_SERVICES.md](NETWORK_SERVICES.md) を参照してください。

## 実行環境

Windows、Windows PowerShell、PowerShell、winget は本プロジェクトに同梱しません。Microsoft およびその他の製品名・商標は各権利者に帰属します。
