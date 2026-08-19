<#
.SYNOPSIS
    ネットワーク接続性を OSI レイヤ順に診断し、どこで止まっているかを特定する。

.DESCRIPTION
    以下の基本 7 段階と品質チェックを順に検査し、各段階の pass/fail/warn と、
    失敗時の考えられる原因・対処方法を JSON で出力する。

    1. L2:           NIC アクティブ確認
    2. L3-local:     IPv4 アドレス取得
    3. L3-routing:   デフォルトゲートウェイ設定
    4. L2/L3:        ゲートウェイ ping + ARP 解決
    5. L3-internet:  外部 IP (1.1.1.1, 8.8.8.8) 到達性
    6. DNS:          ホスト名解決
    7. Application:  HTTPS (443) 接続

    追加で、Wi-Fi品質、連続pingによる遅延/損失/ジッター、DNS/HTTPSの応答時間、
    MTU不一致の兆候を確認し、「つながっているが遅い/止まる」原因候補を出力する。

    さらに Step 2.3 で「リンクは確立しているのに速度が出ない」PC側の構成
    ボトルネック（TCP受信ウィンドウ自動チューニング/RSS の無効化、NICでの IPv6
    無効化、有線リンクのネゴシエーション不足など）を、速度測定なしの設定確認で検出する。

.PARAMETER OutputPath
    出力 JSON のパス

.PARAMETER ExternalIps
    インターネット到達性テスト用の IP リスト

.PARAMETER DnsTestHosts
    DNS 名前解決テスト用のホスト名リスト

.PARAMETER HttpsTestHosts
    HTTPS 接続テスト用のホスト名リスト

.PARAMETER PingTimeoutMs
    ping のタイムアウト (ミリ秒)
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\..\output\network-health.json",
    [string[]]$ExternalIps = @('1.1.1.1', '8.8.8.8'),
    [string[]]$DnsTestHosts = @('www.google.com', 'www.cloudflare.com', 'www.youtube.com'),
    [string[]]$HttpsTestHosts = @('www.google.com', 'github.com', 'www.youtube.com'),
    [int]$PingTimeoutMs = 1500,
    [int]$LocalPingSamples = 12,
    [int]$InternetPingSamples = 8,
    # 外部 IP、公開 DNS/HTTPS、公開 IP 確認、速度測定をすべて省く
    [switch]$NoExternalServices,
    # 実効スループット測定（能動・データ通信あり。既定オフ。-SpeedTest で有効化）
    [switch]$SpeedTest,
    [int]$SpeedTestSeconds = 6,
    # 並列コネクション数。1本だけだと TCP のウィンドウが頭打ちになり、
    # 1Gbps 超の回線で実際より低く出る（fast.com が複数本束ねるのと同じ理由）
    [int]$SpeedTestConnections = 6,
    # 下り測定の通信量上限(MB)。10G 回線では既定値だと数百ミリ秒で使い切るため、
    # 正確に測りたい場合は 2000 程度まで上げる
    [int]$SpeedTestMaxMB = 180,
    # 上り測定の通信量(MB)
    [int]$SpeedTestUploadMB = 20,
    # 宅内(LAN)スループット測定。NAS等の共有フォルダ(例 \\nas\share)を指定した時のみ
    # 実行し、一時ファイルの書き込み/読み取りで LAN 区間の実効速度を測る。
    # インターネット速度と比べることで「宅内が遅いのか回線が遅いのか」を分離できる
    [string]$LanSpeedPath,
    [int]$LanSpeedMB = 200
)

$ErrorActionPreference = "Continue"

if ($NoExternalServices -and $SpeedTest) {
    throw '-NoExternalServices と -SpeedTest は同時に指定できません。'
}

Write-Host "=========================================" -ForegroundColor Magenta
Write-Host " Network Topology Mapper - Diagnostics" -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta

$results = @()
$findings = @()

function Add-Result {
    param(
        [string]$Step,
        [string]$Layer,
        [string]$Status,    # pass / fail / warn / skip
        [string]$Detail,
        $Evidence = $null,
        [string[]]$Hints = @(),
        $Metrics = $null
    )
    $obj = [PSCustomObject]@{
        step     = $Step
        layer    = $Layer
        status   = $Status
        detail   = $Detail
        evidence = $Evidence
        hints    = @($Hints)
        metrics  = $Metrics
    }
    $script:results += $obj

    $color = switch ($Status) {
        'pass' { 'Green' }
        'fail' { 'Red' }
        'warn' { 'Yellow' }
        default { 'DarkGray' }
    }
    $icon = switch ($Status) {
        'pass' { '[+]' }
        'fail' { '[X]' }
        'warn' { '[!]' }
        default { '[~]' }
    }
    Write-Host ("{0} {1,-32} {2}" -f $icon, $Step, $Detail) -ForegroundColor $color
}

function Add-Finding {
    param(
        [string]$Severity,  # high / medium / low
        [string]$Area,
        [string]$Reason,
        [string]$Evidence,
        [string]$Action
    )
    if ([string]::IsNullOrWhiteSpace($Reason)) { return }

    $duplicate = @($script:findings | Where-Object {
        $_.area -eq $Area -and $_.reason -eq $Reason
    }).Count -gt 0
    if ($duplicate) { return }

    $script:findings += [PSCustomObject]@{
        severity = $Severity
        area     = $Area
        reason   = $Reason
        evidence = $Evidence
        action   = $Action
    }
}

function ConvertTo-NumberOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    $s = [string]$Value
    if ($s -match '([0-9]+(?:\.[0-9]+)?)') {
        return [double]$Matches[1]
    }
    return $null
}

function Convert-SpeedTextToMbps {
    # "1 Gbps" / "2.5 Gbps" / "100 Mbps" / "1.0 Gbps Full Duplex" → Mbps(double)。
    # "Auto Negotiation" / "オートネゴシエーション" のように数値が無いものは $null。
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ($Text -match '([0-9]+(?:\.[0-9]+)?)\s*(G|M|K)?\s*bps') {
        $n = [double]$Matches[1]
        switch ($Matches[2]) {
            'G'     { return $n * 1000 }
            'M'     { return $n }
            'K'     { return $n / 1000 }
            default { return [math]::Round($n / 1e6, 3) }  # 単位なし bps
        }
    }
    return $null
}

function Get-AdapterKind {
    param($Adapter)
    if ($null -eq $Adapter) { return "unknown" }
    $text = "$($Adapter.Name) $($Adapter.InterfaceDescription) $($Adapter.MediaType) $($Adapter.NdisPhysicalMedium)"
    if ($text -match '802\.11|Wi-?Fi|Wireless|WLAN|無線') { return "wifi" }
    if ($text -match 'Ethernet|802\.3|有線') { return "wired" }
    return "other"
}

function ConvertFrom-NetshWlanInterfaces {
    # netsh wlan show interfaces の出力行を解釈する。日本語版・英語版の両ラベルに対応。
    # netsh の呼び出しから分離してあるのは、この解釈部分だけをテストできるようにするため。
    param([string[]]$Lines)
    if (-not $Lines) { return $null }

        $info = [ordered]@{
            name             = ""
            state            = ""
            connected        = $false
            ssid             = ""
            bssid            = ""
            signalText       = ""
            signalPercent    = $null
            band             = ""
            channel          = ""
            radio            = ""
            authentication   = ""
            receiveRateMbps  = $null
            transmitRateMbps = $null
        }

        foreach ($line in $Lines) {
            if ($line -match '^\s*(Name|名前)\s*:\s*(.+)$') { $info.name = $Matches[2].Trim(); continue }
            if ($line -match '^\s*(State|状態)\s*:\s*(.+)$') {
                $info.state = $Matches[2].Trim()
                if ($info.state -match 'connected|接続') { $info.connected = $true }
                continue
            }
            if ($line -match '^\s*SSID\s*:\s*(.+)$' -and $line -notmatch 'BSSID') { $info.ssid = $Matches[1].Trim(); continue }
            # Windows 11 は「AP BSSID」と出力する。接頭辞を許容しないと
            # 自分がつないでいる AP を特定できず、混雑判定から除外できない
            if ($line -match '^\s*(?:AP\s+)?BSSID\s*:\s*(.+)$') { $info.bssid = $Matches[1].Trim(); continue }
            if ($line -match '^\s*(Signal|シグナル|信号)\s*:\s*(.+)$') {
                $info.signalText = $Matches[2].Trim()
                $info.signalPercent = ConvertTo-NumberOrNull $info.signalText
                continue
            }
            if ($line -match '^\s*(Band|帯域)\s*:\s*(.+)$') { $info.band = $Matches[2].Trim(); continue }
            if ($line -match '^\s*(Channel|チャネル)\s*:\s*(.+)$') { $info.channel = $Matches[2].Trim(); continue }
            if ($line -match '^\s*(Radio type|無線の種類|電波の種類)\s*:\s*(.+)$') { $info.radio = $Matches[2].Trim(); continue }
            if ($line -match '^\s*(Authentication|認証)\s*:\s*(.+)$') { $info.authentication = $Matches[2].Trim(); continue }
            if ($line -match '^\s*(Receive rate.*|受信.*速度.*|受信.*レート.*)\s*:\s*(.+)$') {
                $info.receiveRateMbps = ConvertTo-NumberOrNull $Matches[2]
                continue
            }
            if ($line -match '^\s*(Transmit rate.*|送信.*速度.*|送信.*レート.*)\s*:\s*(.+)$') {
                $info.transmitRateMbps = ConvertTo-NumberOrNull $Matches[2]
                continue
            }
        }

        if ($info.ssid -or $info.connected) { return [PSCustomObject]$info }
        return $null
}

function Get-WifiInterfaceInfo {
    try {
        $output = @(netsh wlan show interfaces 2>$null)
        if (-not $output -or $LASTEXITCODE -ne 0) { return $null }
        return ConvertFrom-NetshWlanInterfaces -Lines $output
    } catch {
        return $null
    }
}

function Get-ChannelRecommendation {
    <#
        周辺 AP の分布から、移る先のチャネルを具体的に出す。

        評価は「そのチャネルを使ったときに、どれだけ電波が重なるか」の合計。
        重なりの強さは信号強度で重み付けする（弱い AP は実害が小さいため）。

        2.4GHz は 1/6/11 のみを候補にする。それ以外は必ずどこかと半端に
        重なり、かえって悪化するため（日本では 13ch も使えるが、
        1/6/11 の三分割から外れるので候補にしない）。

        5GHz は W52(36-48)/W53(52-64)/W56(100-140) がある。
        W53/W56 は DFS 対象で、気象レーダーを検知すると通信が止まって
        チャネルを移る（1分程度の切断）。安定を優先するなら W52 を勧める。
    #>
    param($Entries, $CurrentChannel, [bool]$Is24)

    if ($null -eq $CurrentChannel) { return $null }

    $candidates = if ($Is24) {
        @(1, 6, 11)
    } else {
        # W52(DFSなし) を優先候補、W56 は空いていることが多いので次点
        @(36, 40, 44, 48, 100, 104, 108, 112, 116, 132, 136, 140)
    }

    # 重なりの重み: 2.4GHz は 5ch 離れるまで影響、5GHz は 20MHz なら同一chのみ
    $scoreOf = {
        param([int]$ch)
        $score = 0.0
        foreach ($e in @($Entries)) {
            if ($null -eq $e.chNum) { continue }
            $sig = if ($null -ne $e.signalPercent) { [double]$e.signalPercent } else { 30.0 }
            $dist = [math]::Abs($e.chNum - $ch)
            if ($Is24) {
                if ($e.chNum -gt 14) { continue }
                if ($dist -eq 0)     { $score += $sig }
                elseif ($dist -le 4) { $score += $sig * (1.0 - ($dist / 5.0)) }
            } else {
                if ($e.chNum -le 14) { continue }
                if ($dist -eq 0)     { $score += $sig }
                elseif ($dist -le 2) { $score += $sig * 0.4 }   # 40MHz 幅での重なり
            }
        }
        return [math]::Round($score, 1)
    }

    $scored = @()
    foreach ($c in $candidates) {
        $scored += [PSCustomObject]@{
            channel = $c
            score   = (& $scoreOf $c)
            dfs     = (-not $Is24 -and $c -ge 52)
            apCount = @($Entries | Where-Object { $_.chNum -eq $c }).Count
        }
    }

    $currentScore = & $scoreOf ([int]$CurrentChannel)

    # DFS なしを優先し、同点なら番号の小さい方
    $best = @($scored | Sort-Object @{ e = { $_.score } }, @{ e = { [int]$_.dfs } }, @{ e = { $_.channel } })[0]
    $bestNoDfs = @($scored | Where-Object { -not $_.dfs } | Sort-Object @{ e = { $_.score } }, @{ e = { $_.channel } })[0]

    # 現在地より意味のある差（3割以上かつ絶対値でも差がある）でなければ勧めない
    $worthMoving = ($null -ne $best) -and
                   ($best.channel -ne [int]$CurrentChannel) -and
                   ($currentScore -gt 0) -and
                   ($best.score -lt ($currentScore * 0.7)) -and
                   (($currentScore - $best.score) -ge 20)

    return [PSCustomObject]@{
        currentChannel   = [int]$CurrentChannel
        currentScore     = $currentScore
        bestChannel      = if ($best) { $best.channel } else { $null }
        bestScore        = if ($best) { $best.score } else { $null }
        bestIsDfs        = if ($best) { [bool]$best.dfs } else { $false }
        bestNonDfsChannel = if ($bestNoDfs) { $bestNoDfs.channel } else { $null }
        bestNonDfsScore   = if ($bestNoDfs) { $bestNoDfs.score } else { $null }
        shouldMove       = $worthMoving
        candidates       = @($scored | Sort-Object score)
    }
}

function Get-RadioKey {
    <#
        BSSID から「物理的な無線機」を識別するキーを作る。

        1 台のルーターが複数の SSID を出していると、BSSID だけが違う AP が
        いくつも見える（例: 02:11:57:c3:90:b4 / b5 / b6 は同じ機械）。
        これを別々の AP として数えると、自分のルーターを「混雑」と誤判定する。

        多くの機器は下位 1 オクテットだけを変えて複数 BSSID を作り、
        先頭オクテットのローカル管理ビット(0x02)を立てる。そこで
        「先頭ビットを落とした上位 5 オクテット」を同一性の基準にする。
    #>
    param([string]$Bssid)
    if (-not $Bssid) { return $null }
    $hex = ($Bssid -replace '[^0-9A-Fa-f]', '').ToUpper()
    if ($hex.Length -lt 12) { return $null }
    $first = [Convert]::ToInt32($hex.Substring(0, 2), 16) -band 0xFC   # ローカル管理/マルチキャストビットを無視
    return ('{0:X2}' -f $first) + $hex.Substring(2, 8)                 # 上位 5 オクテット
}

function Get-WifiNetworkSurvey {
    param(
        [string]$CurrentSsid,
        [string]$CurrentChannel,
        [string]$CurrentBssid
    )

    if ([string]::IsNullOrWhiteSpace($CurrentSsid)) { return $null }
    try {
        $output = @(netsh wlan show networks mode=bssid 2>$null)
        if (-not $output -or $LASTEXITCODE -ne 0) { return $null }

        $entries = @()
        $ssid = ""
        foreach ($line in $output) {
            if ($line -match '^\s*SSID\s+\d+\s*:\s*(.*)$') {
                $ssid = $Matches[1].Trim()
                continue
            }
            if ($line -match '^\s*BSSID\s+\d+\s*:\s*(.+)$') {
                $entries += [PSCustomObject]@{
                    ssid          = $ssid
                    bssid         = $Matches[1].Trim()
                    signalPercent = $null
                    channel       = ""
                }
                continue
            }
            if ($entries.Count -gt 0 -and $line -match '^\s*(Signal|シグナル|信号)\s*:\s*(.+)$') {
                $entries[$entries.Count - 1].signalPercent = ConvertTo-NumberOrNull $Matches[2]
                continue
            }
            if ($entries.Count -gt 0 -and $line -match '^\s*(Channel|チャネル)\s*:\s*(.+)$') {
                $entries[$entries.Count - 1].channel = $Matches[2].Trim()
                continue
            }
        }

        # チャネル番号を整数化（"44" / "44 (5 GHz)" などから先頭の数値を抽出）
        foreach ($e in $entries) {
            $e | Add-Member -NotePropertyName chNum -NotePropertyValue $null -Force
            if ($e.channel -match '(\d+)') { $e.chNum = [int]$Matches[1] }
        }

        $curCh = $null
        if ($CurrentChannel -match '(\d+)') { $curCh = [int]$Matches[1] }

        # --- 同じ無線機がまとめて見えている分を 1 台に畳む ---
        # 自分がつないでいるルーター自身は、チャネルを変えても付いてくるので
        # 「混雑」としては数えない（数えると必ず引っ越しを勧めてしまう）
        $myRadio = Get-RadioKey -Bssid $CurrentBssid
        $allEntries = @($entries)
        $byRadio = @{}
        foreach ($e in $allEntries) {
            $key = (Get-RadioKey -Bssid $e.bssid)
            if (-not $key) { $key = "bssid:$($e.bssid)" }
            $e | Add-Member -NotePropertyName radioKey -NotePropertyValue $key -Force
            $e | Add-Member -NotePropertyName isSelf   -NotePropertyValue ($myRadio -and $key -eq $myRadio) -Force
            # 同じ無線機 x 同じチャネルは 1 件に（信号が強い方を残す）
            $slot = "$key|$($e.chNum)"
            if (-not $byRadio.ContainsKey($slot) -or
                ([int]($e.signalPercent)) -gt ([int]($byRadio[$slot].signalPercent))) {
                $byRadio[$slot] = $e
            }
        }
        $radios = @($byRadio.Values)
        # 混雑の判定に使うのは「自分以外の無線機」
        $entries = @($radios | Where-Object { -not $_.isSelf })
        $selfRadioCount = @($radios | Where-Object { $_.isSelf }).Count

        # バンド判定: ch<=14 → 2.4GHz、それ以外は 5GHz/6GHz とみなす
        $is24 = ($null -ne $curCh -and $curCh -le 14)

        # 同一チャネルで干渉する範囲を判定するヘルパー
        # 2.4GHz: ±4ch 以内は 20MHz 帯が重なる / 5GHz: 80MHz ブロック（36起点16ch幅）が一致
        $blockOf = {
            param($c)
            if ($null -eq $c) { return $null }
            if ($c -le 14) { return "g24" }                       # 2.4GHz はバンド単位
            return "g5_" + [math]::Floor(($c - 36) / 16)          # 5GHz 80MHz ブロック
        }
        $curBlock = & $blockOf $curCh

        $visible = @($entries).Count                      # 自分以外の無線機の数
        $visibleBssidTotal = @($allEntries).Count         # 生の BSSID 数（参考）
        $sameSsid = @($allEntries | Where-Object { $_.ssid -eq $CurrentSsid }).Count

        # 完全一致チャネルの AP 数
        $sameChannel = 0
        if ($null -ne $curCh) {
            $sameChannel = @($entries | Where-Object { $_.chNum -eq $curCh }).Count
        }

        # 同一チャネルかつ強信号（>=50%）の AP 数（実害が出やすい）
        $sameChannelStrong = 0
        if ($null -ne $curCh) {
            $sameChannelStrong = @($entries | Where-Object {
                $_.chNum -eq $curCh -and $null -ne $_.signalPercent -and $_.signalPercent -ge 50
            }).Count
        }

        # 隣接/重複チャネルの AP 数（2.4GHz は ±4ch、5GHz は同一 80MHz ブロック）
        $adjacentOverlap = 0
        if ($null -ne $curCh) {
            $adjacentOverlap = @($entries | Where-Object {
                if ($null -eq $_.chNum) { return $false }
                if ($_.chNum -eq $curCh) { return $false }   # 完全一致は別カウント
                if ($is24) { return ([math]::Abs($_.chNum - $curCh) -le 4) }
                return ((& $blockOf $_.chNum) -eq $curBlock)
            }).Count
        }

        # 最も混雑しているチャネル（参考情報）
        $topChannel = $null; $topChannelCount = 0
        $grp = $entries | Where-Object { $null -ne $_.chNum } | Group-Object chNum | Sort-Object Count -Descending | Select-Object -First 1
        if ($grp) { $topChannel = [int]$grp.Name; $topChannelCount = $grp.Count }

        # 「混んでいる」と言うだけでは動けないので、移る先まで出す
        $recommend = Get-ChannelRecommendation -Entries $entries -CurrentChannel $curCh -Is24 $is24

        return [PSCustomObject]@{
            visibleBssidCount       = $visible          # 自分以外の無線機の台数
            visibleBssidTotal       = $visibleBssidTotal # 見えた BSSID の総数（同一機の複数SSID込み）
            selfBssidCount          = $selfRadioCount
            sameSsidBssidCount      = $sameSsid
            sameChannelBssidCount   = $sameChannel
            sameChannelStrongCount  = $sameChannelStrong
            adjacentOverlapCount    = $adjacentOverlap
            band24                  = $is24
            topChannel              = $topChannel
            topChannelCount         = $topChannelCount
            recommendation          = $recommend
        }
    } catch {
        return $null
    }
}

function Invoke-PingSeries {
    param(
        [string]$Target,
        [int]$Count,
        [int]$TimeoutMs
    )

    $samples = @()
    $failures = @()
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $reply = $ping.Send($Target, $TimeoutMs)
                if ($reply.Status -eq 'Success') {
                    $samples += [double]$reply.RoundtripTime
                } else {
                    $failures += $reply.Status.ToString()
                }
            } catch {
                $failures += 'Error'
            }
            if ($i -lt ($Count - 1)) { Start-Sleep -Milliseconds 120 }
        }
    } finally {
        $ping.Dispose()
    }

    $received = $samples.Count
    $lossPct = if ($Count -gt 0) { [math]::Round((($Count - $received) * 100.0 / $Count), 1) } else { 100 }
    $avg = $null
    $min = $null
    $max = $null
    if ($received -gt 0) {
        $m = $samples | Measure-Object -Minimum -Maximum -Average
        $avg = [math]::Round([double]$m.Average, 1)
        $min = [math]::Round([double]$m.Minimum, 1)
        $max = [math]::Round([double]$m.Maximum, 1)
    }

    $jitter = $null
    if ($samples.Count -gt 1) {
        $diffs = @()
        for ($i = 1; $i -lt $samples.Count; $i++) {
            $diffs += [math]::Abs($samples[$i] - $samples[$i - 1])
        }
        $jitter = [math]::Round([double](($diffs | Measure-Object -Average).Average), 1)
    }

    return [PSCustomObject]@{
        target   = $Target
        sent     = $Count
        received = $received
        lossPct  = $lossPct
        minMs    = $min
        avgMs    = $avg
        maxMs    = $max
        jitterMs = $jitter
        failures = @($failures | Select-Object -Unique)
        samples  = @($samples)
    }
}

function Format-PingStats {
    param($Stats)
    if ($null -eq $Stats) { return "" }
    $avg = if ($null -ne $Stats.avgMs) { "$($Stats.avgMs) ms" } else { "-" }
    $max = if ($null -ne $Stats.maxMs) { "$($Stats.maxMs) ms" } else { "-" }
    $jitter = if ($null -ne $Stats.jitterMs) { "$($Stats.jitterMs) ms" } else { "-" }
    return "target=$($Stats.target); sent=$($Stats.sent); received=$($Stats.received); loss=$($Stats.lossPct)%; avg=$avg; max=$max; jitter=$jitter"
}

function Get-PingQualityStatus {
    param(
        $Stats,
        [string]$Scope
    )
    if ($null -eq $Stats -or $Stats.received -eq 0) { return 'fail' }
    if ($Stats.lossPct -ge 50) { return 'fail' }
    if ($Scope -eq 'local') {
        if ($Stats.lossPct -gt 0 -or $Stats.avgMs -gt 30 -or $Stats.maxMs -gt 120 -or ($Stats.jitterMs -ne $null -and $Stats.jitterMs -gt 25)) { return 'warn' }
    } else {
        if ($Stats.lossPct -gt 0 -or $Stats.avgMs -gt 150 -or $Stats.maxMs -gt 500 -or ($Stats.jitterMs -ne $null -and $Stats.jitterMs -gt 100)) { return 'warn' }
    }
    return 'pass'
}

function Test-MtuProbe {
    # DFビット付き ping の通る最大ペイロードを二分探索し、経路MTUをバイト単位で特定する。
    # 固定4点のプローブでは 1454(PPPoE) と 1460(DS-Lite/MAP-E) を区別できないため。
    # ロスと DF 破棄を区別するため、失敗時は1回だけ再試行する。
    param(
        [string]$Target,
        [int]$TimeoutMs
    )
    $tryPing = {
        param([int]$size)
        # 公共DNS系はDF付き大サイズpingをレート制限で間引くことがあり、
        # 1回の失敗を「通らない」と断定すると MTU を過小評価する。3回まで粘る
        for ($i = 0; $i -lt 3; $i++) {
            $null = & ping.exe -f -n 1 -w $TimeoutMs -l $size $Target 2>$null
            if ($LASTEXITCODE -eq 0) { return $true }
            Start-Sleep -Milliseconds 150
        }
        return $false
    }
    # List は参照型なので、scriptblock 内の Add がこの関数のローカルにそのまま反映される
    # （配列 += は再代入になり子スコープから伝搬しないため使わない）
    $probeRows = New-Object System.Collections.Generic.List[object]
    $probeSize = {
        param([int]$size)
        $ok = & $tryPing $size
        $probeRows.Add([PSCustomObject]@{ payloadBytes = $size; ok = $ok })
        return $ok
    }

    # 下限すら通らないなら ICMP ブロック等で判定不能
    # ※ probes は .ToArray() で渡す。PowerShell 7.6 では New-Object で作った
    #    Generic List を @() で包むと ArgumentException になる
    if (-not (& $probeSize 1200)) {
        return [PSCustomObject]@{
            target = $Target; maxPayload = $null; estimatedMtu = $null
            pathType = $null; probes = $probeRows.ToArray()
        }
    }

    $maxPayload = 1200
    if (& $probeSize 1472) {
        $maxPayload = 1472
    } else {
        # 1200 は通り 1472 は通らない → 間を二分探索（最大 ~8 回）
        $lo = 1200; $hi = 1472
        while (($hi - $lo) -gt 1) {
            $mid = [int](($lo + $hi) / 2)
            if (& $probeSize $mid) { $lo = $mid } else { $hi = $mid }
        }
        $maxPayload = $lo
    }

    $estimatedMtu = $maxPayload + 28
    # 代表値からの接続方式の推定。実測はオプションヘッダ等で代表値から
    # 数バイトずれることがあるため、既知値は完全一致・それ以外は範囲で判定
    $pathType =
        if ($estimatedMtu -ge 1500) { '標準 (1500)' }
        elseif ($estimatedMtu -eq 1492) { 'PPPoE 等 (1492)' }
        elseif ($estimatedMtu -eq 1454) { 'PPPoE (1454)' }
        elseif ($estimatedMtu -eq 1460) { 'IPv4 over IPv6 トンネル (1460)' }
        elseif ($estimatedMtu -ge 1400) { "トンネル/PPPoE 系 ($estimatedMtu)" }
        else { $null }
    return [PSCustomObject]@{
        target       = $Target
        maxPayload   = $maxPayload
        estimatedMtu = $estimatedMtu
        pathType     = $pathType
        probes       = $probeRows.ToArray()
    }
}

function Test-CgnIp {
    # キャリアNAT用の共有アドレス 100.64.0.0/10 (RFC 6598) か
    param([string]$Ip)
    if ($Ip -match '^100\.(\d+)\.') { $o = [int]$Matches[1]; return ($o -ge 64 -and $o -le 127) }
    return $false
}

function Test-PrivateIp {
    # RFC1918 / CGN (100.64/10) / link-local 判定
    param([string]$Ip)
    if (-not $Ip) { return $false }
    if ($Ip -like '10.*')      { return $true }
    if ($Ip -like '192.168.*') { return $true }
    if ($Ip -like '169.254.*') { return $true }
    if ($Ip -match '^172\.(\d+)\.') { $o = [int]$Matches[1]; if ($o -ge 16 -and $o -le 31) { return $true } }
    if (Test-CgnIp $Ip) { return $true }
    return $false
}

function Get-FirstHops {
    # tracert で最初の数ホップの IP を取得（二重NAT検出用）
    param([string]$Target = '8.8.8.8', [int]$MaxHops = 4)
    $hops = @()
    try {
        $output = & tracert -d -h $MaxHops -w 800 $Target 2>$null
        foreach ($line in $output) {
            if ($line -match '^\s*(\d+)\s+.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$') {
                $hops += [PSCustomObject]@{ hop = [int]$Matches[1]; ip = $Matches[2] }
            }
        }
    } catch { }
    return @($hops)
}

$script:SpeedUA = 'NetworkTopologyMapper/1.0'

function Initialize-HttpType {
    # PS 5.1 では System.Net.Http が未ロードのことがある。PS7 では既にあるので二重ロードを避ける
    if (-not ('System.Net.Http.HttpClient' -as [type])) { try { Add-Type -AssemblyName System.Net.Http } catch { } }
}

# ----------------------------------------------------------------------
# 並列コネクションでの速度測定
#   1本の TCP コネクションでは、遅延のある経路や 1Gbps 超の回線で
#   受信ウィンドウが頭打ちになり、回線に余力があっても数百 Mbps で止まる。
#   fast.com / speedtest.net が複数コネクションを束ねているのはこのため。
#   ここでも複数本を同時に流して合算する。
#
#   スレッド化は RunspacePool を使う（PowerShell 5.1 でも動くため。
#   ForEach-Object -Parallel は PS7 以上、ScriptBlock → デリゲート変換は
#   別スレッドから呼ぶと不安定）。
# ----------------------------------------------------------------------

$script:DownloadWorker = {
    param([string]$Url, [double]$MaxSeconds, [long]$MaxBytes, [string]$UserAgent, [double]$RampSeconds)
    try {
        if (-not ('System.Net.Http.HttpClient' -as [type])) { try { Add-Type -AssemblyName System.Net.Http } catch { } }
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($MaxSeconds + 20)
        $client.DefaultRequestHeaders.Add('User-Agent', $UserAgent)
        $buffer = New-Object byte[] 262144
        $total = 0L
        $rampBytes = 0L; $rampAt = 0.0; $ramped = $false
        $ok = $false
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        # 測定先によって 1 リクエストで返せるサイズに上限がある
        # （Cloudflare は 100MB 未満）。時間枠を埋めるためリクエストを繰り返す。
        # HttpClient を使い回すので TCP コネクションは張り直されない。
        while ($sw.Elapsed.TotalSeconds -lt $MaxSeconds -and $total -lt $MaxBytes) {
            $resp = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
            if (-not $resp.IsSuccessStatusCode) { $resp.Dispose(); break }
            $ok = $true
            $stream = $resp.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            while ($sw.Elapsed.TotalSeconds -lt $MaxSeconds -and $total -lt $MaxBytes) {
                $read = $stream.Read($buffer, 0, $buffer.Length)
                if ($read -le 0) { break }
                $total += $read
                # 立ち上がり(スロースタート)を除いた区間を別途記録する
                if (-not $ramped -and $sw.Elapsed.TotalSeconds -ge $RampSeconds) {
                    $ramped = $true
                    $rampBytes = $total
                    $rampAt = $sw.Elapsed.TotalSeconds
                }
            }
            $stream.Dispose(); $resp.Dispose()
        }
        $sw.Stop()
        $client.Dispose()
        if (-not $ok) { return $null }

        [PSCustomObject]@{
            totalBytes  = $total
            elapsedSec  = $sw.Elapsed.TotalSeconds
            steadyBytes = if ($ramped) { $total - $rampBytes } else { 0L }
            steadySec   = if ($ramped) { $sw.Elapsed.TotalSeconds - $rampAt } else { 0.0 }
        }
    } catch { return $null }
}

$script:UploadWorker = {
    param([string]$Url, [long]$Bytes, [string]$UserAgent, [double]$TimeoutSec)
    try {
        if (-not ('System.Net.Http.HttpClient' -as [type])) { try { Add-Type -AssemblyName System.Net.Http } catch { } }
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $client.DefaultRequestHeaders.Add('User-Agent', $UserAgent)
        $payload = New-Object byte[] $Bytes
        # New-Object だと byte[] が引数リストとして展開されてしまうため ::new を使う
        $content = [System.Net.Http.ByteArrayContent]::new($payload)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $resp = $client.PostAsync($Url, $content).GetAwaiter().GetResult()
        $sw.Stop()
        $ok = $resp.IsSuccessStatusCode
        $resp.Dispose(); $client.Dispose()
        if (-not $ok) { return $null }
        [PSCustomObject]@{ totalBytes = $Bytes; elapsedSec = $sw.Elapsed.TotalSeconds }
    } catch { return $null }
}

function Start-ParallelWorkers {
    # 同じスクリプトブロックを N 本、同時に走らせ始める（完了は待たない）。
    # 負荷をかけながら別の測定をしたい（バッファブロート測定）ため、
    # 起動と待ち合わせを分けてある。
    param([scriptblock]$Worker, [array]$ArgumentSets)
    $count = @($ArgumentSets).Count
    if ($count -le 0) { return $null }

    $pool = [runspacefactory]::CreateRunspacePool(1, $count)
    $pool.Open()
    $running = @()
    foreach ($argSet in $ArgumentSets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($Worker.ToString())
        foreach ($a in $argSet) { [void]$ps.AddArgument($a) }
        $running += [PSCustomObject]@{ ps = $ps; handle = $ps.BeginInvoke() }
    }
    return [PSCustomObject]@{ pool = $pool; running = $running }
}

function Wait-ParallelWorkers {
    # Start-ParallelWorkers の結果を待ち合わせて集める
    param($Job)
    if (-not $Job) { return @() }
    $results = @()
    foreach ($r in $Job.running) {
        try { $results += @($r.ps.EndInvoke($r.handle)) } catch { }
        try { $r.ps.Dispose() } catch { }
    }
    try { $Job.pool.Close(); $Job.pool.Dispose() } catch { }
    return @($results | Where-Object { $_ })
}

function Invoke-ParallelWorkers {
    # 起動して完了まで待つ（従来どおりの使い方）
    param([scriptblock]$Worker, [array]$ArgumentSets)
    if (@($ArgumentSets).Count -le 0) { return @() }
    $job = Start-ParallelWorkers -Worker $Worker -ArgumentSets $ArgumentSets
    return Wait-ParallelWorkers -Job $job
}

function Measure-DownloadMbps {
    # 複数の測定エンドポイントを順に試し、最初に成功したもので実効 Mbps を返す。
    # ツール名と版を示す User-Agent を付与する。
    # 戻り値は測定条件込みのオブジェクト（失敗時 null）。
    param(
        [int]$MaxSeconds = 6,
        [long]$MaxBytes = 500MB,     # 全コネクション合計の上限（通信量の歯止め）
        [int]$Connections = 6,
        [double]$RampSeconds = 1.5,  # 立ち上がりとして計算から除く秒数
        # 負荷がかかっている最中に実行したい処理（バッファブロート測定用）。
        # ダウンロードの開始直後に呼ばれ、戻り値は $script:LoadProbeResult に入る
        [scriptblock]$WhileLoaded
    )
    Initialize-HttpType
    if ($Connections -lt 1) { $Connections = 1 }
    # 立ち上がり除去後に十分な測定区間が残らない設定では、除去自体をやめる
    if ($MaxSeconds -le ($RampSeconds + 1.0)) { $RampSeconds = 0 }

    # Cloudflare の bytes は 100,000,000 以上を指定すると 403 になるため上限内に収める
    # （足りない分はワーカ側でリクエストを繰り返して埋める）
    $urls = @('https://speed.cloudflare.com/__down?bytes=99000000')
    $perConn = [long]([math]::Floor($MaxBytes / $Connections))

    foreach ($url in $urls) {
        try {
            $argSets = @()
            for ($i = 0; $i -lt $Connections; $i++) {
                $argSets += , @($url, [double]$MaxSeconds, $perConn, $script:SpeedUA, [double]$RampSeconds)
            }
            $job = Start-ParallelWorkers -Worker $script:DownloadWorker -ArgumentSets $argSets
            if ($WhileLoaded) {
                # 回線が埋まっている最中に測る。立ち上がりを避けるため少し待ってから
                Start-Sleep -Milliseconds ([int]($RampSeconds * 1000))
                try {
                    $script:LoadProbeResult = & $WhileLoaded
                } catch {
                    Write-Host "[!] 負荷時の測定に失敗: $($_.Exception.Message)" -ForegroundColor Yellow
                    $script:LoadProbeResult = $null
                }
            }
            $res = Wait-ParallelWorkers -Job $job
            if (@($res).Count -eq 0) { continue }

            $totalBytes = ($res | Measure-Object -Property totalBytes -Sum).Sum
            $maxElapsed = ($res | Measure-Object -Property elapsedSec -Maximum).Maximum
            if ($totalBytes -lt 2MB -or $maxElapsed -le 0.2) { continue }

            # 立ち上がりを除いた区間が各コネクションに十分あれば、そこだけで算出する。
            # 各コネクションの安定時レートを足したものが回線としての実効値。
            $steady = @($res | Where-Object { $_.steadySec -gt 0.5 -and $_.steadyBytes -gt 0 })
            if ($steady.Count -eq @($res).Count) {
                $mbps = 0.0
                foreach ($s in $steady) { $mbps += ($s.steadyBytes * 8) / ($s.steadySec * 1e6) }
                $window = ($steady | Measure-Object -Property steadySec -Maximum).Maximum
                $method = 'steady'
            } else {
                $mbps = ($totalBytes * 8) / ($maxElapsed * 1e6)
                $window = $maxElapsed
                $method = 'whole'
            }

            return [PSCustomObject]@{
                mbps        = [math]::Round($mbps, 1)
                connections = @($res).Count
                totalMB     = [math]::Round($totalBytes / 1MB, 1)
                windowSec   = [math]::Round($window, 1)
                capped      = ($totalBytes -ge ($MaxBytes * 0.98))
                method      = $method
                url         = $url
            }
        } catch { }
    }
    return $null
}

function Measure-UploadMbps {
    # 並列 POST で上り実効 Mbps の目安を返す（サーバ処理を含む参考値。失敗時は null）
    param(
        [long]$TotalBytes = 60MB,
        [int]$Connections = 4,
        [int]$TimeoutSec = 40,
        [string]$Url = 'https://speed.cloudflare.com/__up'
    )
    Initialize-HttpType
    if ($Connections -lt 1) { $Connections = 1 }
    $perConn = [long]([math]::Floor($TotalBytes / $Connections))
    if ($perConn -lt 1MB) { $perConn = 1MB }

    try {
        $argSets = @()
        for ($i = 0; $i -lt $Connections; $i++) {
            $argSets += , @($Url, $perConn, $script:SpeedUA, [double]$TimeoutSec)
        }
        $res = Invoke-ParallelWorkers -Worker $script:UploadWorker -ArgumentSets $argSets
        if (@($res).Count -eq 0) { return $null }

        # 送信サイズ固定なので終了時刻がばらつく。合計バイト ÷ 全体の所要時間で見る
        $sum = ($res | Measure-Object -Property totalBytes -Sum).Sum
        $maxElapsed = ($res | Measure-Object -Property elapsedSec -Maximum).Maximum
        if ($maxElapsed -le 0.2) { return $null }

        return [PSCustomObject]@{
            mbps        = [math]::Round(($sum * 8) / ($maxElapsed * 1e6), 1)
            connections = @($res).Count
            totalMB     = [math]::Round($sum / 1MB, 1)
        }
    } catch { return $null }
}

function Measure-LanThroughput {
    # 共有フォルダへ一時ファイルを書き込み→読み取りし、LAN 区間の実効 Mbps を測る。
    # 読み取りは FILE_FLAG_NO_BUFFERING で SMB クライアントキャッシュを迂回する
    # （書いた直後のファイルはキャッシュから読めてしまい、実測にならないため）。
    # ネットワークファイルではローカルディスクのようなアライメント制約が緩いが、
    # 念のため失敗時は通常読み取りへフォールバックし、その旨を返す。
    param(
        [string]$Path,
        [int]$SizeMB = 200
    )
    if (-not (Test-Path $Path)) { return $null }
    $file = Join-Path $Path ("ntm-lanspeed-" + [guid]::NewGuid().ToString('N') + ".tmp")
    $chunk = 4MB
    $buf = New-Object byte[] $chunk
    (New-Object System.Random).NextBytes($buf)
    $total = [long]$SizeMB * 1MB
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        # 書き込み（PC → 対向）。WriteThrough で書き込み完了まで待つ。
        # Write が途中で失敗(容量不足等)してもハンドルを残さないよう finally で閉じる。
        # 閉じ損ねると外側 finally の Remove-Item が黙って失敗し、一時ファイルが対向に残る
        $written = [long]0
        $fs = New-Object System.IO.FileStream($file, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 1MB, [System.IO.FileOptions]::WriteThrough)
        try {
            while ($written -lt $total) { $fs.Write($buf, 0, $chunk); $written += $chunk }
            $fs.Flush($true)
        } finally { $fs.Dispose() }
        $writeSec = $sw.Elapsed.TotalSeconds
        $writeMbps = if ($writeSec -gt 0.2) { [math]::Round(($written * 8) / ($writeSec * 1e6), 1) } else { $null }

        # 読み取り（対向 → PC）
        $readMethod = 'unbuffered'
        $read = [long]0
        $sw.Restart()
        try {
            $noBuffering = [System.IO.FileOptions]0x20000000
            $fs = New-Object System.IO.FileStream($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $chunk, $noBuffering)
            try {
                while (($n = $fs.Read($buf, 0, $chunk)) -gt 0) { $read += $n }
            } finally { $fs.Dispose() }
        } catch {
            $readMethod = 'buffered'
            $read = [long]0
            $sw.Restart()
            $fs = New-Object System.IO.FileStream($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read, $chunk, [System.IO.FileOptions]::SequentialScan)
            try {
                while (($n = $fs.Read($buf, 0, $chunk)) -gt 0) { $read += $n }
            } finally { $fs.Dispose() }
        }
        $readSec = $sw.Elapsed.TotalSeconds
        $readMbps = if ($readSec -gt 0.2 -and $read -gt 0) { [math]::Round(($read * 8) / ($readSec * 1e6), 1) } else { $null }

        return [PSCustomObject]@{
            path       = $Path
            sizeMB     = [math]::Round($written / 1MB, 0)
            writeMbps  = $writeMbps
            readMbps   = $readMbps
            readMethod = $readMethod
        }
    } catch {
        return $null
    } finally {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
    }
}

function Get-CpuLoadSample {
    # CPU 使用率と DPC/割り込み時間(%)を1点取得する。
    # Get-Counter はカウンタ名が OS の言語で変わり日本語環境で壊れやすいため、
    # ロケール非依存の WMI パフォーマンスクラスを使う
    try {
        $p = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
        if ($p) {
            return [PSCustomObject]@{
                cpuPct       = [double]$p.PercentProcessorTime
                dpcPct       = [double]$p.PercentDPCTime
                interruptPct = [double]$p.PercentInterruptTime
            }
        }
    } catch { }
    return $null
}

function Get-TcpRetransSnapshot {
    # TCP 送信/再送セグメントの累積カウンタ(OS起動時から)。
    # 速度測定の前後で差分を取り「測定中の再送率」を出す。
    # PerfFormattedData は1点取得だと値が出ないことがあるため Raw(累積値)を使う。
    # プロパティ名は *Persec だが Raw クラスでは累積カウントが入っている。
    # IPoE 環境では実トラフィックが IPv6 側を通ることがあるため v4+v6 を合算する
    $sent = [double]0; $retrans = [double]0; $got = $false
    foreach ($cls in 'Win32_PerfRawData_Tcpip_TCPv4', 'Win32_PerfRawData_Tcpip_TCPv6') {
        try {
            $r = Get-CimInstance -ClassName $cls -ErrorAction Stop
            if ($r) {
                $sent    += [double]$r.SegmentsSentPersec
                $retrans += [double]$r.SegmentsRetransmittedPersec
                $got = $true
            }
        } catch { }
    }
    if ($got) { return [PSCustomObject]@{ sent = $sent; retrans = $retrans } }
    return $null
}

function Measure-HttpTiming {
    # 1つの HTTPS アクセスを DNS解決 / TCP接続 / TLSハンドシェイク / TTFB に分解して測る。
    # 「速度は出るのにブラウジングが重い」原因がどのフェーズにあるかを切り分ける。
    # TLS だけ突出して遅い場合はセキュリティソフトの TLS 検査(MITM)が典型
    param([string]$TargetHost, [int]$Port = 443, [int]$TimeoutMs = 5000)
    $r = [ordered]@{ targetHost = $TargetHost; dnsMs = $null; tcpMs = $null; tlsMs = $null; ttfbMs = $null; ok = $false }
    $tcp = $null; $ssl = $null
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $ips = [System.Net.Dns]::GetHostAddresses($TargetHost)
        $r.dnsMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
        $ip = @($ips | Where-Object { $_.AddressFamily -eq 'InterNetwork' })[0]
        if (-not $ip) { $ip = @($ips)[0] }
        if (-not $ip) { return [PSCustomObject]$r }

        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ReceiveTimeout = $TimeoutMs
        $tcp.SendTimeout = $TimeoutMs
        $sw.Restart()
        $ar = $tcp.BeginConnect($ip, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw 'connect timeout' }
        $tcp.EndConnect($ar)
        $r.tcpMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false)
        $sw.Restart()
        $ssl.AuthenticateAsClient($TargetHost)
        $r.tlsMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

        $reqText = "HEAD / HTTP/1.1`r`nHost: $TargetHost`r`nUser-Agent: $($script:SpeedUA)`r`nConnection: close`r`n`r`n"
        $reqBytes = [System.Text.Encoding]::ASCII.GetBytes($reqText)
        $sw.Restart()
        $ssl.Write($reqBytes, 0, $reqBytes.Length)
        $ssl.Flush()
        $one = New-Object byte[] 1
        if (($ssl.Read($one, 0, 1)) -gt 0) {
            $r.ttfbMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
            $r.ok = $true
        }
    } catch {
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch { } }
        if ($tcp) { try { $tcp.Close() } catch { } }
    }
    return [PSCustomObject]$r
}

function Test-Ipv6Connectivity {
    # 外部IPv6への到達性（Cloudflare / Google の v6）
    param([int]$TimeoutMs = 1500)
    $targets = @('2606:4700:4700::1111', '2001:4860:4860::8888')
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        foreach ($t in $targets) {
            try { if (($ping.Send($t, $TimeoutMs)).Status -eq 'Success') { return $true } } catch { }
        }
    } finally { $ping.Dispose() }
    return $false
}

function Get-GlobalIpv6 {
    # 主アダプタのグローバルIPv6(GUA: 2000::/3)を1件返す。fe80/ULA は除外
    param($Adapter)
    if (-not $Adapter) { return $null }
    try {
        $a = Get-NetIPAddress -InterfaceIndex $Adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -match '^[23]' -and $_.IPAddress -notmatch '^(fe80|fc|fd)' } |
             Select-Object -First 1
        if ($a) { return $a.IPAddress }
    } catch { }
    return $null
}

# ======================================================================
# Step 1: NIC アクティブ確認
# ======================================================================
Write-Host "`n--- Step 1: L2 (物理/データリンク) ---" -ForegroundColor Cyan
$activeAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
    $_.Status -eq 'Up' -and $_.MediaConnectionState -eq 'Connected'
})

if ($activeAdapters.Count -eq 0) {
    Add-Finding -Severity 'high' -Area 'L2/NIC' `
        -Reason 'アクティブなネットワークアダプタがない' `
        -Evidence 'Get-NetAdapter で Up/Connected のNICが見つかりません' `
        -Action 'Wi-Fiの接続状態、機内モード、有線ケーブル、アダプタドライバを確認してください'
    Add-Result -Step "アクティブな NIC" -Layer "L2" -Status "fail" `
        -Detail "アクティブなネットワークアダプタがありません" `
        -Hints @(
            "Wi-Fi: Wi-Fi が ON か確認、機内モード解除、SSID に接続",
            "有線: LAN ケーブルを挿し直す、別のポート/ケーブルを試す",
            "デバイスマネージャーでアダプタが認識されているか確認",
            "ドライバの再インストール"
        )
    # NIC がなければ以降は意味がないのでここで保存して終了
    $output = [PSCustomObject]@{
        summary = [PSCustomObject]@{
            timestamp     = (Get-Date).ToString("o")
            overallStatus = "fail"
            pass          = 0
            fail          = 1
            warn          = 0
            skip          = 0
            total         = 1
            stoppedAt     = "L2 - NIC"
            likelyCauses  = @($findings)
        }
        results = $results
    }
    $outDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $output | ConvertTo-Json -Depth 10 | Set-Content $OutputPath -Encoding UTF8
    Write-Host "`n[!] L2 で停止しました。診断を中断します。" -ForegroundColor Red
    return
}
Add-Result -Step "アクティブな NIC" -Layer "L2" -Status "pass" `
    -Detail "$($activeAdapters.Count) 個のアクティブな NIC を検出" `
    -Evidence (@($activeAdapters | ForEach-Object { "$($_.Name): $($_.InterfaceDescription)" }))

# ======================================================================
# Step 1.5: NIC エラー/破棄統計 (物理層の品質)
# ======================================================================
Write-Host "`n--- Step 1.5: L1/L2 (NICエラー統計) ---" -ForegroundColor Cyan
# ここの累積値は起動時からの合算で「過去の問題か現在進行中か」を区別できない。
# 診断終了時(Step 8.5)に再取得して増加量(Δ)で判定するため、基準値を保持する。
$script:nicStatBaseline     = @{}
$script:nicStatBaselineTime = Get-Date
$nicStatRows = @()
$nicStatStatus = 'pass'
$nicStatHints = @()
$nicStatDetails = @()
foreach ($na in $activeAdapters) {
    $st = $null
    try { $st = Get-NetAdapterStatistics -Name $na.Name -ErrorAction Stop } catch { }
    if (-not $st) { continue }

    $rxPkts = [double]($st.ReceivedUnicastPackets + $st.ReceivedMulticastPackets + $st.ReceivedBroadcastPackets)
    $txPkts = [double]($st.SentUnicastPackets + $st.SentMulticastPackets + $st.SentBroadcastPackets)
    $rxErr  = [double]($st.ReceivedPacketErrors)
    $txErr  = [double]($st.OutboundPacketErrors)
    $rxDisc = [double]($st.ReceivedDiscardedPackets)
    $txDisc = [double]($st.OutboundDiscardedPackets)
    $totalPkts = $rxPkts + $txPkts
    $totalErr  = $rxErr + $txErr
    $totalDisc = $rxDisc + $txDisc

    $script:nicStatBaseline[$na.Name] = [PSCustomObject]@{
        rxDelivered = $rxPkts
        rxErr       = $rxErr
        txErr       = $txErr
        rxDisc      = $rxDisc
        txDisc      = $txDisc
    }

    # エラー率を ppm (百万分率) で算出。カウンタは起動時からの累積。
    $errPpm  = if ($totalPkts -gt 0) { [math]::Round(($totalErr / $totalPkts) * 1e6, 1) } else { 0 }
    $discPpm = if ($totalPkts -gt 0) { [math]::Round(($totalDisc / $totalPkts) * 1e6, 1) } else { 0 }

    $nicStatRows += [PSCustomObject]@{
        name        = $na.Name
        rxPackets   = [long]$rxPkts
        txPackets   = [long]$txPkts
        rxErrors    = [long]$rxErr
        txErrors    = [long]$txErr
        rxDiscards  = [long]$rxDisc
        txDiscards  = [long]$txDisc
        errorPpm    = $errPpm
        discardPpm  = $discPpm
    }
    $nicStatDetails += "$($na.Name): err=$([long]$totalErr) disc=$([long]$totalDisc) (errPpm=$errPpm)"

    # 判定: 累積エラーがある程度あり、かつ率がしきい値超過なら警告。
    # 100ppm(0.01%)超で warn、1000ppm(0.1%)超で実害が出やすい。
    if ($totalErr -ge 20 -and $errPpm -ge 1000) {
        $nicStatStatus = 'warn'
        $nicStatHints += "$($na.Name) の受信/送信エラー率が高めです(errPpm=$errPpm)。ケーブル不良・接触不良・ドライバ・電波干渉(Wi-Fi)が疑われます"
        Add-Finding -Severity 'medium' -Area 'L1/L2物理' `
            -Reason 'NICのパケットエラー率が高い' `
            -Evidence "$($na.Name): rxErr=$([long]$rxErr), txErr=$([long]$txErr), errPpm=$errPpm" `
            -Action '有線ならLANケーブル/ポート交換、Wi-Fiなら距離/干渉/ドライバ更新を確認してください'
    } elseif ($totalErr -ge 20 -and $errPpm -ge 100) {
        if ($nicStatStatus -eq 'pass') { $nicStatStatus = 'warn' }
        $nicStatHints += "$($na.Name) に軽度のパケットエラーがあります(errPpm=$errPpm)。様子見でよいが増加するなら物理層を確認"
    }
    if ($totalDisc -ge 100 -and $discPpm -ge 1000) {
        if ($nicStatStatus -eq 'pass') { $nicStatStatus = 'warn' }
        $nicStatHints += "$($na.Name) の破棄パケットが多めです(discPpm=$discPpm)。バッファ溢れ・過負荷・ドライバの可能性"
        Add-Finding -Severity 'low' -Area 'L1/L2物理' `
            -Reason 'NICの破棄パケットが多い' `
            -Evidence "$($na.Name): rxDisc=$([long]$rxDisc), txDisc=$([long]$txDisc), discPpm=$discPpm" `
            -Action 'ドライバ更新、省電力設定の無効化、過負荷の有無を確認してください'
    }
}
if ($nicStatRows.Count -gt 0) {
    if ($nicStatStatus -eq 'pass') { $nicStatHints += "累積パケットエラー/破棄はしきい値内です（起動時からの累積値）" }
    Add-Result -Step "NICエラー統計" -Layer "L1/L2" -Status $nicStatStatus `
        -Detail ($nicStatDetails -join ' | ') `
        -Evidence "値はOS起動時からの累積。率(ppm)で評価しています" `
        -Hints $nicStatHints `
        -Metrics ([PSCustomObject]@{ adapters = @($nicStatRows) })
} else {
    Add-Result -Step "NICエラー統計" -Layer "L1/L2" -Status "skip" `
        -Detail "統計カウンタを取得できませんでした（ドライバ非対応の可能性）"
}

# ======================================================================
# Step 2: IPv4 アドレス取得
# ======================================================================
Write-Host "`n--- Step 2: L3-local (IP アドレス) ---" -ForegroundColor Cyan

$primaryAdapter = $null
$primaryIp      = $null
$primaryConfig  = $null
$apipaOnly      = $false

foreach ($a in $activeAdapters) {
    $config = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
    if (-not $config) { continue }
    $validIps = @($config.IPv4Address | Where-Object {
        $_.IPAddress -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1'
    })
    if ($validIps.Count -gt 0 -and $config.IPv4DefaultGateway) {
        $primaryAdapter = $a
        $primaryIp      = $validIps[0].IPAddress
        $primaryConfig  = $config
        break
    }
    # APIPA だけかチェック
    if ($config.IPv4Address -and (@($config.IPv4Address | Where-Object { $_.IPAddress -like '169.254.*' }).Count -gt 0)) {
        $apipaOnly = $true
    }
}

if (-not $primaryIp) {
    if ($apipaOnly) {
        Add-Finding -Severity 'high' -Area 'DHCP' `
            -Reason 'DHCP から IPv4 アドレスを取得できていない' `
            -Evidence 'APIPA (169.254.x.x) のみ検出' `
            -Action 'Wi-Fi再接続、ルーター再起動、DHCPプール/固定IP設定を確認してください'
        Add-Result -Step "IPv4 アドレス取得" -Layer "L3-local" -Status "fail" `
            -Detail "APIPA (169.254.x.x) のみ - DHCP サーバーから IP を取得できていません" `
            -Hints @(
                "ルーター(DHCPサーバー)に L2 では届いているが DHCP が応答していない",
                "ルーターを再起動してみる",
                "Wi-Fi の場合: 一旦切断して再接続",
                "管理者権限の PowerShell で: ipconfig /release / ipconfig /renew",
                "ルーターの DHCP サーバー機能が有効か管理画面で確認",
                "DHCP プールが枯渇していないか確認 (ルーター側のリース表示)"
            )
    } else {
        Add-Finding -Severity 'high' -Area 'IP設定' `
            -Reason '有効な IPv4 アドレスがない' `
            -Evidence 'IPv4アドレスまたはデフォルトゲートウェイが未取得' `
            -Action 'DHCPまたは静的IP設定を確認してください'
        Add-Result -Step "IPv4 アドレス取得" -Layer "L3-local" -Status "fail" `
            -Detail "有効な IPv4 アドレスもデフォルトゲートウェイも取得できていません" `
            -Hints @(
                "NIC は up しているが IP が割り当てられていない",
                "DHCP の応答がない、または静的 IP 設定の不備",
                "ipconfig /all で詳細を確認"
            )
    }
} else {
    Add-Result -Step "IPv4 アドレス取得" -Layer "L3-local" -Status "pass" `
        -Detail "$primaryIp ($($primaryAdapter.Name))" `
        -Evidence "$primaryIp / $($primaryConfig.IPv4Address[0].PrefixLength) on $($primaryAdapter.InterfaceDescription)"
}

# ======================================================================
# Step 2.3: スループット準備状況（リンク速度 / TCP設定 / IPv6）
#   「リンクは確立しているのに速度が出ない」PC側の構成ボトルネックを検出する。
#   速度測定は行わず、設定面の準備状況のみを確認する（すべて読み取り・管理者権限不要）。
# ======================================================================
Write-Host "`n--- Step 2.3: スループット準備状況 (リンク速度/TCP/IPv6) ---" -ForegroundColor Cyan

# 基準アダプタ: 主経路を優先、なければ最初の物理NIC、それも無ければ最初のアクティブNIC
$speedAdapter = if ($primaryAdapter) {
    $primaryAdapter
} else {
    $phys = @($activeAdapters | Where-Object { $_.HardwareInterface -eq $true -and -not $_.Virtual })
    if ($phys.Count -gt 0) { $phys[0] } else { @($activeAdapters)[0] }
}

# --- (A) 有線リンク速度 / NIC 詳細設定（仮想・USB等は除外し物理有線のみ）---
$primaryWired = $null
$wiredAdapters = @($activeAdapters | Where-Object {
    (Get-AdapterKind -Adapter $_) -eq 'wired' -and $_.HardwareInterface -eq $true -and -not $_.Virtual
})
if ($wiredAdapters.Count -gt 0) {
    $linkRows = @()
    $linkStatus = 'pass'
    $linkHints = @()
    foreach ($wa in $wiredAdapters) {
        $negMbps = Convert-SpeedTextToMbps $wa.LinkSpeed

        # NIC 詳細設定を1回取得して再利用（速度デュプレックス・EEE）
        $adv = $null
        try { $adv = @(Get-NetAdapterAdvancedProperty -Name $wa.Name -ErrorAction SilentlyContinue) } catch { }
        $maxMbps = $null
        $duplexValue = $null
        $sd = $adv | Where-Object { $_.RegistryKeyword -eq '*SpeedDuplex' } | Select-Object -First 1
        if ($sd) {
            $duplexValue = [string]$sd.DisplayValue
            if ($sd.ValidDisplayValues) {
                foreach ($vdv in $sd.ValidDisplayValues) {
                    $m = Convert-SpeedTextToMbps ([string]$vdv)
                    if ($null -ne $m -and ($null -eq $maxMbps -or $m -gt $maxMbps)) { $maxMbps = $m }
                }
            }
        }
        $eeeOn = $false
        $eee = $adv | Where-Object { $_.RegistryKeyword -match 'EEE' -or $_.DisplayName -match '省電力イーサ|Energy.?Efficient' } | Select-Object -First 1
        if ($eee -and ([string]$eee.DisplayValue) -match 'On|有効|オン|Enabled') { $eeeOn = $true }

        # 受信バッファ(Receive Buffers)。高速リンクで既定値のままだと、
        # バースト受信でバッファが溢れ「エラー0なのに受信破棄だけ増える」形で現れる
        $rxBufVal = $null; $rxBufMax = $null
        $rb = $adv | Where-Object { $_.RegistryKeyword -eq '*ReceiveBuffers' } | Select-Object -First 1
        if ($rb) {
            $v = 0
            if ([int]::TryParse([string](@($rb.RegistryValue)[0]), [ref]$v)) { $rxBufVal = $v }
            if ($rb.NumericParameterMaxValue) {
                $m = 0
                if ([int]::TryParse([string]$rb.NumericParameterMaxValue, [ref]$m)) { $rxBufMax = $m }
            }
        }

        # PCIe 接続情報。イーサネットのリンク速度がいくら速くても、NICとCPU間の
        # PCIe 帯域が細ければそこで頭打ちになる(例: Gen2 x1 ≒ 4Gbps に 10GbE NIC)。
        # Encoded 値: 1=Gen1, 2=Gen2, 3=Gen3, 4=Gen4, 5=Gen5。
        # 実効帯域はエンコードオーバーヘッド込みの概算(Gen1/2=8b10b, Gen3以降=128b130b)。
        $pcieCurGen = $null; $pcieCurWidth = $null; $pcieMaxGen = $null; $pcieMaxWidth = $null; $pcieMbps = $null
        $hw = $null
        try { $hw = Get-NetAdapterHardwareInfo -Name $wa.Name -ErrorAction Stop } catch { }
        if ($hw) {
            if ([int]$hw.PciExpressCurrentLinkSpeedEncoded -gt 0) { $pcieCurGen   = [int]$hw.PciExpressCurrentLinkSpeedEncoded }
            if ([int]$hw.PciExpressCurrentLinkWidth -gt 0)        { $pcieCurWidth = [int]$hw.PciExpressCurrentLinkWidth }
            if ([int]$hw.PciExpressMaxLinkSpeedEncoded -gt 0)     { $pcieMaxGen   = [int]$hw.PciExpressMaxLinkSpeedEncoded }
            if ([int]$hw.PciExpressMaxLinkWidth -gt 0)            { $pcieMaxWidth = [int]$hw.PciExpressMaxLinkWidth }
            $perLaneMbps = @{ 1 = 2000; 2 = 4000; 3 = 7880; 4 = 15750; 5 = 31500 }
            if ($pcieCurGen -and $pcieCurWidth -and $perLaneMbps.ContainsKey($pcieCurGen)) {
                $pcieMbps = $perLaneMbps[$pcieCurGen] * $pcieCurWidth
            }
        }

        $driverAgeYears = $null
        if ($wa.DriverDate) {
            try { $driverAgeYears = [math]::Round(((Get-Date) - [datetime]$wa.DriverDate).TotalDays / 365.0, 1) } catch { }
        }

        $linkRows += [PSCustomObject]@{
            name             = $wa.Name
            linkMbps         = $negMbps
            maxSupportedMbps = $maxMbps
            speedDuplex      = $duplexValue
            eeeEnabled       = $eeeOn
            driverVersion    = [string]$wa.DriverVersion
            driverAgeYears   = $driverAgeYears
            expectedMbps     = if ($negMbps) { [math]::Round($negMbps * 0.94) } else { $null }
            pcieGen          = $pcieCurGen
            pcieWidth        = $pcieCurWidth
            pcieMaxGen       = $pcieMaxGen
            pcieMaxWidth     = $pcieMaxWidth
            pcieBandwidthMbps = $pcieMbps
            rxBuffers        = $rxBufVal
            rxBuffersMax     = $rxBufMax
            rxBufferIncreaseRecommended = $false
        }

        # 低速リンク（有線で 100Mbps 以下）
        if ($null -ne $negMbps -and $negMbps -le 100) {
            $linkStatus = 'warn'
            $linkHints += "$($wa.Name) のリンクが $($wa.LinkSpeed) です。ケーブル不良/古い規格/ポート劣化で 1Gbps を割っている可能性があります"
            Add-Finding -Severity 'medium' -Area 'リンク速度' `
                -Reason '有線リンクが 100Mbps 以下でネゴシエーションされている' `
                -Evidence "$($wa.Name): link=$($wa.LinkSpeed)" `
                -Action 'LANケーブル(Cat5e以上)とポートを交換し、両端を差し直して 1Gbps にリンクするか確認してください'
        }
        # ネゴシエーション不足（対応最大速度 >> 実リンク速度）
        elseif ($null -ne $negMbps -and $null -ne $maxMbps -and $maxMbps -ge ($negMbps * 2)) {
            if ($linkStatus -eq 'pass') { $linkStatus = 'warn' }
            $linkHints += "$($wa.Name) は最大 $([int]$maxMbps)Mbps 対応ですが $([int]$negMbps)Mbps でリンクしています。ケーブルのカテゴリ・対向ポート・配線長を確認してください（10G=Cat6A、2.5G/1G=Cat5e以上）"
            Add-Finding -Severity 'medium' -Area 'リンク速度' `
                -Reason 'NICの対応速度より低い速度でリンクしている' `
                -Evidence "$($wa.Name): max=$([int]$maxMbps)Mbps, link=$([int]$negMbps)Mbps, speedDuplex=$duplexValue" `
                -Action 'ケーブルを Cat6A 等の上位カテゴリへ、対向(スイッチ/ルータ)ポートの対応速度、配線長(最大100m)を確認してください'
        }

        # PCIe 帯域がイーサネットのリンク速度を下回っている → NICより手前が律速
        if ($null -ne $pcieMbps -and $null -ne $negMbps -and $pcieMbps -lt $negMbps) {
            $linkStatus = 'warn'
            $linkHints += "$($wa.Name) は PCIe Gen$pcieCurGen x$pcieCurWidth（実効 ~$([int]$pcieMbps)Mbps）で接続されており、イーサネットリンク $([int]$negMbps)Mbps を PCIe 側が頭打ちにします"
            Add-Finding -Severity 'high' -Area 'PCIe帯域' `
                -Reason 'NICのPCIe帯域がイーサネットのリンク速度を下回っている' `
                -Evidence "$($wa.Name): PCIe Gen$pcieCurGen x$pcieCurWidth (~$([int]$pcieMbps)Mbps) < link $([int]$negMbps)Mbps" `
                -Action 'カードを上位のスロット(CPU直結や x4 スロット)へ挿し替える、BIOS でスロットの PCIe 世代設定を確認してください'
        }
        # 対応世代より低い世代でリンク（帯域は足りていても、挿し直し等で改善余地）
        elseif ($pcieCurGen -and $pcieMaxGen -and $pcieCurGen -lt $pcieMaxGen) {
            $linkHints += "$($wa.Name) は PCIe Gen$pcieMaxGen 対応ですが Gen$pcieCurGen x$pcieCurWidth で接続中です。現状の帯域(~$([int]$pcieMbps)Mbps)はリンク速度に足りているため実害はありませんが、カードの挿し直しやスロット変更で本来の世代に戻せる場合があります"
        }
        # PCIe 情報が取得でき、帯域も十分 → 事実として明示（切り分け済みの安心材料）
        elseif ($pcieCurGen -and $pcieCurWidth) {
            $linkHints += "$($wa.Name) は PCIe Gen$pcieCurGen x$pcieCurWidth（実効 ~$([int]$pcieMbps)Mbps）で接続。PCIe 側はボトルネックではありません"
        }
        # 2.5GbE 以上なのに PCIe 情報が取れない場合のみ、判定不能であることを伝える
        elseif ($null -ne $negMbps -and $negMbps -ge 2500) {
            $linkHints += "$($wa.Name) はドライバが PCIe 情報を提供しておらず、PCIe 世代/レーン幅を判定できません（GPU-Z や HWiNFO で確認できます）"
        }

        # 受信バッファが最大値未満で、このNICに受信破棄の実績がある
        #   → バッファ増量で改善する見込みが高い(Repair-NetworkSetting が自動修復対象にする)
        if ($null -ne $rxBufVal -and $null -ne $rxBufMax -and $rxBufVal -lt $rxBufMax) {
            $discRow = @($nicStatRows | Where-Object { $_.name -eq $wa.Name })[0]
            $rxDiscCum = if ($discRow) { [long]$discRow.rxDiscards } else { 0 }
            if ($rxDiscCum -ge 100) {
                if ($linkStatus -eq 'pass') { $linkStatus = 'warn' }
                $linkRows[-1].rxBufferIncreaseRecommended = $true
                $linkHints += "$($wa.Name) の受信バッファが $rxBufVal（最大 $rxBufMax）のまま、受信破棄が累積 $rxDiscCum 件あります。バッファ増量で破棄が減る見込みが高い組み合わせです"
                Add-Finding -Severity 'medium' -Area 'NIC受信バッファ' `
                    -Reason '受信バッファが最大値未満で、受信破棄の実績がある' `
                    -Evidence "$($wa.Name): ReceiveBuffers=$rxBufVal/$rxBufMax, rxDiscards=$rxDiscCum" `
                    -Action "Repair-NetworkSetting.ps1 で自動修復できます（手動: Set-NetAdapterAdvancedProperty -Name '$($wa.Name)' -RegistryKeyword '*ReceiveBuffers' -RegistryValue $rxBufMax。適用時に数秒リンクが切れます）"
            } elseif ($null -ne $negMbps -and $negMbps -ge 2500 -and $rxBufVal -le ($rxBufMax / 4)) {
                $linkHints += "$($wa.Name) の受信バッファは $rxBufVal（最大 $rxBufMax）です。破棄は出ていませんが、$([int]$negMbps)Mbps リンクでは増量の余地があります"
            }
        }

        # 速度/デュプレックスが手動固定（通常はオート推奨）
        if ($duplexValue -and $duplexValue -notmatch 'Auto|オート|自動') {
            $linkHints += "$($wa.Name) の「速度とデュプレックス」が手動設定($duplexValue)です。通常はオートネゴシエーションを推奨します"
        }
        # 省電力イーサネット(EEE)が有効
        if ($eeeOn) {
            $linkHints += "$($wa.Name) は省電力イーサネット(EEE)が有効です。速度が不安定なときは無効化を試す価値があります"
        }
        # ドライバが古い
        if ($null -ne $driverAgeYears -and $driverAgeYears -ge 3) {
            $linkHints += "$($wa.Name) のNICドライバが約 $driverAgeYears 年前です($($wa.DriverVersion))。メーカー最新ドライバへの更新を検討してください"
        }
    }

    $primaryWired = $linkRows | Where-Object { $_.name -eq $speedAdapter.Name } | Select-Object -First 1
    if (-not $primaryWired) { $primaryWired = $linkRows | Select-Object -First 1 }
    $linkDetail = ($linkRows | ForEach-Object {
        $exp  = if ($_.expectedMbps) { " (実効目安 ~$($_.expectedMbps)Mbps)" } else { "" }
        $pcie = if ($_.pcieGen -and $_.pcieWidth) { " / PCIe Gen$($_.pcieGen) x$($_.pcieWidth)" } else { "" }
        "$($_.name): $([int]$_.linkMbps)Mbps$exp$pcie"
    }) -join ' | '
    if ($linkStatus -eq 'pass') {
        $linkHints += "有線リンク速度・NIC設定に明らかな問題はありません（実効スループットはリンク速度の約9割が目安）"
    }
    Add-Result -Step "有線リンク速度/NIC設定" -Layer "L1/L2" -Status $linkStatus `
        -Detail $linkDetail `
        -Evidence "速度測定ではなくリンク速度とNIC設定の確認です" `
        -Hints $linkHints `
        -Metrics ([PSCustomObject]@{ adapters = @($linkRows) })
}

# --- (B) TCP/IP スタック設定 (RSS / 受信ウィンドウ自動チューニング) ---
#   日本語版/英語版どちらの netsh 出力でも拾えるようにラベルを両対応で照合する。
#   値(enabled/disabled/normal 等)は JP Windows でも英語で出力される。
$rss = $null; $autotune = $null
try {
    $tcpGlobal = @(& netsh int tcp show global 2>$null)
    foreach ($line in $tcpGlobal) {
        if ($line -match '^\s*Receive-Side Scaling.*?[:：]\s*([A-Za-z]+)') { $rss = $Matches[1].ToLower(); continue }
        if ($line -match '(Receive Window Auto-Tuning Level|自動チューニング).*?[:：]\s*([A-Za-z]+)') { $autotune = $Matches[2].ToLower(); continue }
    }
} catch { }
# netsh はテキスト出力の言語・形式・取りこぼしに左右されるため、
# 取れなかった値はロケール非依存の CIM から補完する
if (-not $autotune) {
    try {
        $tcpSetting = Get-NetTCPSetting -SettingName Internet -ErrorAction Stop
        if ($tcpSetting -and $tcpSetting.AutoTuningLevelLocal) { $autotune = ([string]$tcpSetting.AutoTuningLevelLocal).ToLower() }
    } catch { }
}
if (-not $rss) {
    try {
        $offloadGlobal = Get-NetOffloadGlobalSetting -ErrorAction Stop
        if ($offloadGlobal -and $offloadGlobal.ReceiveSideScaling) { $rss = ([string]$offloadGlobal.ReceiveSideScaling).ToLower() }
    } catch { }
}

if ($null -ne $rss -or $null -ne $autotune) {
    $tcpStatus = 'pass'
    $tcpHints = @()
    $primaryLinkMbps = if ($primaryWired -and $primaryWired.linkMbps) { [int]$primaryWired.linkMbps } else { $null }
    $linkFast = ($null -ne $primaryLinkMbps -and $primaryLinkMbps -ge 1000)

    if ($autotune -and $autotune -ne 'normal') {
        if ($autotune -eq 'disabled') {
            $tcpStatus = 'warn'
            $tcpHints += "TCP受信ウィンドウ自動チューニングが『disabled』です。高速回線で数百Mbps止まりになる典型的な原因です"
            $sev = if ($linkFast) { 'high' } else { 'medium' }
            Add-Finding -Severity $sev -Area 'TCP設定' `
                -Reason 'TCP受信ウィンドウ自動チューニングが無効' `
                -Evidence "autotuninglevel=$autotune; linkMbps=$primaryLinkMbps" `
                -Action '管理者PowerShellで: netsh int tcp set global autotuninglevel=normal （過去の高速化/最適化ツールが無効化していることが多い）'
        } else {
            if ($tcpStatus -eq 'pass') { $tcpStatus = 'warn' }
            $tcpHints += "TCP受信ウィンドウ自動チューニングが『$autotune』です。通常は normal が推奨で、制限値だと帯域を使い切れないことがあります"
            Add-Finding -Severity 'medium' -Area 'TCP設定' `
                -Reason "TCP自動チューニングが normal 以外($autotune)" `
                -Evidence "autotuninglevel=$autotune" `
                -Action '管理者PowerShellで: netsh int tcp set global autotuninglevel=normal'
        }
    }
    if ($rss -eq 'disabled') {
        $tcpStatus = 'warn'
        $tcpHints += "Receive-Side Scaling(RSS)が無効です。受信処理が1コアに集中し、高速回線で頭打ちになります"
        $sev = if ($linkFast) { 'high' } else { 'medium' }
        Add-Finding -Severity $sev -Area 'TCP設定' `
            -Reason 'Receive-Side Scaling(RSS)が無効' `
            -Evidence "rss=$rss; linkMbps=$primaryLinkMbps" `
            -Action '管理者PowerShellで: netsh int tcp set global rss=enabled （必要に応じて Enable-NetAdapterRss -Name "<NIC名>"）'
    }
    # 主経路NICのRSSキュー数。グローバルでRSS有効でも、NIC側が無効/1キューだと
    # 受信処理が1コアに集中し、2.5GbE 以上で頭打ちの原因になる
    $rssQueues = $null; $rssAdapterEnabled = $null
    if ($speedAdapter) {
        $adapterRss = $null
        try { $adapterRss = Get-NetAdapterRss -Name $speedAdapter.Name -ErrorAction Stop } catch { }
        if ($adapterRss) {
            $rssAdapterEnabled = [bool]$adapterRss.Enabled
            if ($null -ne $adapterRss.NumberOfReceiveQueues) { $rssQueues = [int]$adapterRss.NumberOfReceiveQueues }
            $fastLink = ($primaryLinkMbps -and $primaryLinkMbps -ge 2500)
            if (-not $rssAdapterEnabled -and $fastLink) {
                if ($tcpStatus -eq 'pass') { $tcpStatus = 'warn' }
                $tcpHints += "$($speedAdapter.Name) 側の RSS が無効です。$primaryLinkMbps Mbps リンクでは受信が1コア処理になり頭打ちします"
                Add-Finding -Severity 'medium' -Area 'TCP設定' `
                    -Reason '高速リンクのNICでRSSが無効' `
                    -Evidence "$($speedAdapter.Name): RSS Enabled=False; link=$primaryLinkMbps Mbps" `
                    -Action "管理者PowerShellで: Enable-NetAdapterRss -Name '$($speedAdapter.Name)'"
            } elseif ($rssAdapterEnabled -and $rssQueues -eq 1 -and $fastLink) {
                $tcpHints += "$($speedAdapter.Name) の RSS キューが 1 本です。複数コアに分散できておらず、高速リンクでは CPU 律速になりやすい構成です（NICドライバの詳細設定で RSS キュー数を確認）"
            }
        }
    }
    if ($tcpStatus -eq 'pass') {
        $tcpHints += "RSS=有効 / 自動チューニング=normal で、TCPスタックは高速通信向けの設定です"
    }
    Add-Result -Step "TCP/IP スタック設定" -Layer "L4/TCP" -Status $tcpStatus `
        -Detail "RSS=$rss; 受信ウィンドウ自動チューニング=$autotune$(if ($null -ne $rssQueues) { "; RSSキュー=$rssQueues" })" `
        -Evidence "netsh int tcp show global / Get-NetAdapterRss の値（読み取りのみ・管理者権限不要）" `
        -Hints $tcpHints `
        -Metrics ([PSCustomObject]@{ rss = $rss; autoTuningLevel = $autotune; adapterRssEnabled = $rssAdapterEnabled; rssQueues = $rssQueues })
}

# --- (C) IPv6 有効状態 + WAN経路（IPoE/DS-Lite vs PPPoE の手掛かり）---
if ($speedAdapter) {
    $v6bind = $null
    try { $v6bind = Get-NetAdapterBinding -Name $speedAdapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue } catch { }
    if ($v6bind -and -not $v6bind.Enabled) {
        Add-Result -Step "IPv6 / WAN経路" -Layer "L3" -Status "warn" `
            -Detail "$($speedAdapter.Name): IPv6 バインドが無効" `
            -Evidence "ms_tcpip6 Enabled=False" `
            -Hints @(
                "このNICで IPv6(ms_tcpip6) が無効化されています",
                "IPv6 経由の高速な接続方式(IPoE / IPv4 over IPv6)は IPv6 が前提です。無効だと混雑しやすい IPv4 PPPoE 経路に固定され、速度が出ないことがあります",
                '有効化(管理者PowerShell): Enable-NetAdapterBinding -Name "<NIC名>" -ComponentID ms_tcpip6'
            )
        Add-Finding -Severity 'medium' -Area 'IPv6/WAN' `
            -Reason 'NICで IPv6 が無効化されている' `
            -Evidence "$($speedAdapter.Name): ms_tcpip6 Enabled=False" `
            -Action 'IPoE/IPv4 over IPv6 を使う回線では IPv6 を有効化してください: Enable-NetAdapterBinding -Name "<NIC名>" -ComponentID ms_tcpip6'
    } elseif ($v6bind -and $NoExternalServices) {
        $gua = Get-GlobalIpv6 -Adapter $speedAdapter
        Add-Result -Step "IPv6 / WAN経路" -Layer "L3" -Status "skip" `
            -Detail "IPv6 は有効$(if ($gua) { "（GUA=$gua）" } else { '' })。外部到達確認は省略" `
            -Evidence "ms_tcpip6 Enabled=True; -NoExternalServices" `
            -Hints @('外部 IPv6 への ping は送信していません')
    } elseif ($v6bind) {
        $gua  = Get-GlobalIpv6 -Adapter $speedAdapter
        $v6ok = Test-Ipv6Connectivity
        if ($gua -and $v6ok) {
            Add-Result -Step "IPv6 / WAN経路" -Layer "L3-internet" -Status "pass" `
                -Detail "IPv6 利用可（GUA=$gua、外部IPv6到達OK）" `
                -Evidence "ms_tcpip6 Enabled=True; ping6 OK" `
                -Hints @("IPv6 経由の高速な接続方式(IPoE / IPv4 over IPv6)が使える状態です。実際の接続方式はルータの設定画面で確認できます")
        } elseif ($gua -and -not $v6ok) {
            Add-Result -Step "IPv6 / WAN経路" -Layer "L3-internet" -Status "warn" `
                -Detail "IPv6 アドレスはあるが外部IPv6に到達できません（GUA=$gua）" `
                -Evidence "ms_tcpip6 Enabled=True; ping6 NG" `
                -Hints @("ルータ/上流のIPv6経路、またはセキュリティソフトのIPv6遮断を確認してください")
            Add-Finding -Severity 'low' -Area 'IPv6/WAN' -Reason 'IPv6アドレスはあるが外部到達不可' `
                -Evidence "GUA=$gua; ping6 NG" -Action 'ルータのIPv6設定/上流開通、セキュリティソフトのIPv6遮断を確認してください'
        } else {
            Add-Result -Step "IPv6 / WAN経路" -Layer "L3" -Status "warn" `
                -Detail "IPv6 は有効だがグローバルIPv6 未取得（プレフィックス未配布/上流未開通の可能性）" `
                -Evidence "ms_tcpip6 Enabled=True; GUA なし" `
                -Hints @(
                    # 以前は取得できていたのに消えた場合、原因は回線ではなく
                    # ルータ広告(RA)の取りこぼし。再接続で直ることが多いので最初に案内する
                    "以前は IPv6 が使えていたのに取得できなくなった場合は、まず接続の再確立を試してください。Wi-Fi なら一度切断して繋ぎ直す、有線ならケーブルを抜き差しすると、ルータへ再度問い合わせて取り直します"
                    "それでも取得できない場合は、ルータがIPv6プレフィックスを配布しているか、回線のIPv6/IPoEが開通済みかを確認してください"
                    "IPv4 over IPv6 (MAP-E/DS-Lite) を使っている場合、IPv4 が通っている時点でルータのWAN側IPv6は生きています。その状態でGUAが取れないなら、原因はLAN側への配布（RA）です"
                )
            Add-Finding -Severity 'low' -Area 'IPv6/WAN' -Reason 'IPv6有効だがグローバルIPv6未取得' `
                -Evidence "$($speedAdapter.Name): GUA なし" -Action 'ルータのIPv6配布/回線のIPoE開通を確認してください'
        }
    }
}

# Step 8(スループット相関)用に、PC側で判明した事実をスクリプトスコープへ退避
$script:primaryLinkMbps = if ($primaryWired -and $primaryWired.linkMbps) { [int]$primaryWired.linkMbps } else { $null }
$script:rssState        = $rss
$script:autotuneState   = $autotune
$script:ipv6BindEnabled = if ($v6bind) { [bool]$v6bind.Enabled } else { $null }

# ======================================================================
# Step 2.5: Wi-Fi 品質（接続している場合）
# ======================================================================
Write-Host "`n--- Step 2.5: Wi-Fi (無線品質) ---" -ForegroundColor Cyan
$primaryAdapterKind = Get-AdapterKind -Adapter $primaryAdapter
$wifiInfo = Get-WifiInterfaceInfo
$wifiSurvey = $null

if ($wifiInfo -and $wifiInfo.ssid) {
    $wifiSurvey = Get-WifiNetworkSurvey -CurrentSsid $wifiInfo.ssid -CurrentChannel $wifiInfo.channel -CurrentBssid $wifiInfo.bssid
    $wifiStatus = 'pass'
    $wifiHints = @()

    if ($null -ne $wifiInfo.signalPercent -and $wifiInfo.signalPercent -lt 50) {
        $wifiStatus = 'warn'
        $wifiHints += "Wi-Fi 信号が弱めです。50% 未満では動画停止、再送、レイテンシ上昇が出やすくなります"
        $wifiHints += "AP/ルーターに近づく、PC の向きを変える、中継器/メッシュの位置を見直す"
        Add-Finding -Severity 'medium' -Area 'Wi-Fi' `
            -Reason 'Wi-Fi の信号強度が低い' `
            -Evidence "signal=$($wifiInfo.signalText), SSID=$($wifiInfo.ssid)" `
            -Action 'APとの距離・障害物・中継器配置を確認し、可能なら5GHz/6GHzまたは有線で比較してください'
    }

    $rateLow = $false
    if ($null -ne $wifiInfo.receiveRateMbps -and $wifiInfo.receiveRateMbps -lt 72) { $rateLow = $true }
    if ($null -ne $wifiInfo.transmitRateMbps -and $wifiInfo.transmitRateMbps -lt 72) { $rateLow = $true }
    if ($rateLow) {
        $wifiStatus = 'warn'
        $wifiHints += "Wi-Fi のリンク速度が低めです。電波干渉、遠距離、古い規格、2.4GHz接続が原因になり得ます"
        Add-Finding -Severity 'medium' -Area 'Wi-Fi' `
            -Reason 'Wi-Fi のリンク速度が低い' `
            -Evidence "rx=$($wifiInfo.receiveRateMbps) Mbps, tx=$($wifiInfo.transmitRateMbps) Mbps" `
            -Action '5GHz/6GHz SSIDに切り替える、ルーターのチャネル幅/設置位置/子機ドライバを確認してください'
    }

    if ($wifiSurvey) {
        # (a) 同一チャネルに強信号(>=50%)のAPが複数 → 実害が出やすい混雑
        if ($wifiSurvey.sameChannelStrongCount -ge 2) {
            $wifiStatus = 'warn'
            $wifiHints += "同一チャネル($($wifiInfo.channel))に、自分以外の強い電波のAPが $($wifiSurvey.sameChannelStrongCount) 台あり、エアタイム競合・遅延の原因になり得ます"
            Add-Finding -Severity 'medium' -Area 'Wi-Fi干渉' `
                -Reason '同一チャネルに強信号の他APが複数' `
                -Evidence "channel=$($wifiInfo.channel), sameChannelStrong(>=50%)=$($wifiSurvey.sameChannelStrongCount), sameChannelTotal=$($wifiSurvey.sameChannelBssidCount)" `
                -Action 'ルーターの自動チャネル再実行、または混雑の少ないチャネル/5GHz/6GHzへ変更してください'
        }
        # (b) 同一チャネルAP総数が多い（弱信号含む）
        elseif ($wifiSurvey.sameChannelBssidCount -ge 5) {
            $wifiStatus = 'warn'
            $wifiHints += "同じチャネルのアクセスポイントが多く($($wifiSurvey.sameChannelBssidCount)個)、近隣 Wi-Fi との干渉が疑われます"
            Add-Finding -Severity 'medium' -Area 'Wi-Fi干渉' `
                -Reason '同一チャネルの Wi-Fi が多い' `
                -Evidence "channel=$($wifiInfo.channel), sameChannelBssidCount=$($wifiSurvey.sameChannelBssidCount)" `
                -Action 'ルーターの自動チャネルを再実行するか、混雑の少ないチャネル/5GHz/6GHzへ変更してください'
        }

        # (c) 隣接/重複チャネルの混雑（2.4GHz=±4ch、5GHz=同一80MHzブロック）
        $adjThreshold = if ($wifiSurvey.band24) { 3 } else { 4 }
        if ($wifiSurvey.adjacentOverlapCount -ge $adjThreshold) {
            if ($wifiStatus -eq 'pass') { $wifiStatus = 'warn' }
            $bandHint = if ($wifiSurvey.band24) {
                "2.4GHzは1/6/11以外だと隣接チャネル干渉が起きやすいです。1/6/11のいずれかへ"
            } else {
                "5GHzでも同一80MHzブロック(例:36/40/44/48)が混むと影響します。別のブロックや幅(40/80→20MHz)を検討"
            }
            $wifiHints += "隣接/重複チャネルにAPが $($wifiSurvey.adjacentOverlapCount) 個あります。$bandHint"
            Add-Finding -Severity 'low' -Area 'Wi-Fi干渉' `
                -Reason '隣接・重複チャネルのAPが多い' `
                -Evidence "channel=$($wifiInfo.channel), adjacentOverlapCount=$($wifiSurvey.adjacentOverlapCount), mostCrowdedCh=$($wifiSurvey.topChannel)($($wifiSurvey.topChannelCount))" `
                -Action $bandHint
        }

        # 混んでいると言うだけでは動けないので、移る先のチャネルまで示す
        $rec = $wifiSurvey.recommendation
        if ($rec -and $rec.shouldMove -and $rec.bestChannel) {
            $moveText = "ルーターの Wi-Fi チャネルを $($rec.currentChannel) から $($rec.bestChannel) に変えると混雑が減ります"
            if ($rec.bestIsDfs) {
                # DFS 帯はレーダー検知で 1 分ほど通信が止まることがある
                $moveText += "（$($rec.bestChannel)ch は DFS 帯です。気象レーダーを検知すると一時的に通信が止まります。安定を優先するなら $($rec.bestNonDfsChannel)ch を選んでください）"
            }
            $wifiHints += $moveText
            if ($wifiStatus -eq 'pass') { $wifiStatus = 'warn' }
            Add-Finding -Severity 'low' -Area 'Wi-Fi干渉' `
                -Reason '現在のチャネルより空いているチャネルがある' `
                -Evidence "current=$($rec.currentChannel)(混雑度 $($rec.currentScore)) → 推奨=$($rec.bestChannel)(混雑度 $($rec.bestScore))" `
                -Action $moveText
        }
    }

    $bandText = [string]$wifiInfo.band
    if ($bandText -match '2\.4|2.4|2 GHz|2GHz') {
        $wifiHints += "2.4GHz は電子レンジ/Bluetooth/近隣APの影響を受けやすいため、動画や会議では 5GHz/6GHz の比較が有効です"
    }

    $surveyText = ""
    if ($wifiSurvey) {
        $surveyText = "; visibleBssid=$($wifiSurvey.visibleBssidCount); sameSsidBssid=$($wifiSurvey.sameSsidBssidCount); sameChannelBssid=$($wifiSurvey.sameChannelBssidCount); sameChannelStrong=$($wifiSurvey.sameChannelStrongCount); adjacentOverlap=$($wifiSurvey.adjacentOverlapCount); mostCrowdedCh=$($wifiSurvey.topChannel)"
    }

    $rateText = ""
    if ($null -ne $wifiInfo.receiveRateMbps -or $null -ne $wifiInfo.transmitRateMbps) {
        $rateText = "; Rx/Tx=$($wifiInfo.receiveRateMbps)/$($wifiInfo.transmitRateMbps) Mbps"
    }

    # Step 8 でスループットと比較する基準（主経路が Wi-Fi のときはこちらを使う）。
    # 受信レートを採るのは、下り測定と対応させるため。
    $script:primaryWifiPhyMbps = @($wifiInfo.receiveRateMbps, $wifiInfo.transmitRateMbps) |
                                 Where-Object { $_ } | Select-Object -First 1

    Add-Result -Step "Wi-Fi 無線品質" -Layer "L1/L2" -Status $wifiStatus `
        -Detail "SSID=$($wifiInfo.ssid), Signal=$($wifiInfo.signalText), Band=$($wifiInfo.band), Ch=$($wifiInfo.channel)$rateText" `
        -Evidence "BSSID=$($wifiInfo.bssid); Radio=$($wifiInfo.radio); Auth=$($wifiInfo.authentication)$surveyText" `
        -Hints $wifiHints `
        -Metrics ([PSCustomObject]@{
            ssid                  = $wifiInfo.ssid
            bssid                 = $wifiInfo.bssid
            signalPercent         = $wifiInfo.signalPercent
            band                  = $wifiInfo.band
            channel               = $wifiInfo.channel
            radio                 = $wifiInfo.radio
            receiveRateMbps       = $wifiInfo.receiveRateMbps
            transmitRateMbps      = $wifiInfo.transmitRateMbps
            visibleBssidCount      = if ($wifiSurvey) { $wifiSurvey.visibleBssidCount } else { $null }
            visibleBssidTotal      = if ($wifiSurvey) { $wifiSurvey.visibleBssidTotal } else { $null }
            selfBssidCount         = if ($wifiSurvey) { $wifiSurvey.selfBssidCount } else { $null }
            channelRecommendation  = if ($wifiSurvey) { $wifiSurvey.recommendation } else { $null }
            sameSsidBssidCount     = if ($wifiSurvey) { $wifiSurvey.sameSsidBssidCount } else { $null }
            sameChannelBssidCount  = if ($wifiSurvey) { $wifiSurvey.sameChannelBssidCount } else { $null }
            sameChannelStrongCount = if ($wifiSurvey) { $wifiSurvey.sameChannelStrongCount } else { $null }
            adjacentOverlapCount   = if ($wifiSurvey) { $wifiSurvey.adjacentOverlapCount } else { $null }
            mostCrowdedChannel     = if ($wifiSurvey) { $wifiSurvey.topChannel } else { $null }
        })
} else {
    $wifiDetail = if ($primaryAdapterKind -eq 'wifi') {
        "Wi-Fi アダプタが主経路の可能性がありますが、netsh から接続情報を取得できません"
    } else {
        "現在の主経路は Wi-Fi ではない、または Wi-Fi 接続を検出していません"
    }
    Add-Result -Step "Wi-Fi 無線品質" -Layer "L1/L2" -Status "skip" -Detail $wifiDetail
}

# ======================================================================
# Step 3: デフォルトゲートウェイ設定確認
# ======================================================================
Write-Host "`n--- Step 3: L3-routing (デフォルトゲートウェイ) ---" -ForegroundColor Cyan
$gw = $null
if ($primaryConfig -and $primaryConfig.IPv4DefaultGateway) {
    $gw = $primaryConfig.IPv4DefaultGateway[0].NextHop
}

if (-not $gw) {
    Add-Finding -Severity 'high' -Area 'ルーティング' `
        -Reason 'デフォルトゲートウェイが設定されていない' `
        -Evidence '0.0.0.0/0 の出口がありません' `
        -Action 'DHCP配布設定または静的IPのゲートウェイ設定を確認してください'
    Add-Result -Step "デフォルトゲートウェイ設定" -Layer "L3-routing" -Status "fail" `
        -Detail "デフォルトゲートウェイが設定されていません" `
        -Hints @(
            "DHCP からゲートウェイ情報を受信できていない",
            "静的 IP 設定の場合、ゲートウェイを正しく設定する",
            "route print でルーティングテーブルを確認 (0.0.0.0 のエントリがあるか)"
        )
} else {
    Add-Result -Step "デフォルトゲートウェイ設定" -Layer "L3-routing" -Status "pass" `
        -Detail "$gw" -Evidence $gw
}

# ======================================================================
# Step 4: ゲートウェイ到達性 (ARP + ping)
# ======================================================================
$gwReachable = $false
$gatewayQualityStats = $null
if ($gw) {
    Write-Host "`n--- Step 4: L2/L3 (ゲートウェイ到達性) ---" -ForegroundColor Cyan

    # ARP テーブル確認
    $arp = Get-NetNeighbor -IPAddress $gw -ErrorAction SilentlyContinue |
           Where-Object { $_.State -in 'Reachable', 'Stale', 'Permanent' } | Select-Object -First 1
    # 接続先ネットワークの識別に使う（自宅・出先で診断値を混ぜないため）
    if ($arp -and $arp.LinkLayerAddress) { $script:gatewayMac = ($arp.LinkLayerAddress -replace '[^0-9A-Fa-f]', '').ToUpper() }
    if ($arp -and $arp.LinkLayerAddress) {
        Add-Result -Step "ゲートウェイ ARP 解決" -Layer "L2" -Status "pass" `
            -Detail "MAC: $($arp.LinkLayerAddress) [$($arp.State)]" `
            -Evidence "$($arp.LinkLayerAddress) ($($arp.State))"
    } else {
        Add-Result -Step "ゲートウェイ ARP 解決" -Layer "L2" -Status "warn" `
            -Detail "ARP テーブルにゲートウェイのエントリなし" `
            -Hints @(
                "L2 でゲートウェイに到達できていない可能性",
                "Wi-Fi: 信号強度を確認、AP の近くで試す",
                "有線: ケーブル/スイッチを確認"
            )
    }

    # ping
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $reply = $ping.Send($gw, $PingTimeoutMs)
        if ($reply.Status -eq 'Success') {
            $gwReachable = $true
            Add-Result -Step "ゲートウェイ ping" -Layer "L3-local" -Status "pass" `
                -Detail "$gw に到達 ($($reply.RoundtripTime) ms)" `
                -Evidence "RTT: $($reply.RoundtripTime) ms"
        } else {
            $pingStatus = if ($arp -and $arp.LinkLayerAddress) { "warn" } else { "fail" }
            Add-Result -Step "ゲートウェイ ping" -Layer "L3-local" -Status $pingStatus `
                -Detail "$gw に到達できません ($($reply.Status))" `
                -Hints @(
                    "ルーター/AP が応答していない",
                    "ゲートウェイで ICMP がブロックされている可能性 (ARP が成功していれば実は通信できている)",
                    "ルーターを再起動",
                    "Wi-Fi: 信号強度を確認、SSID を確認、再接続",
                    "Windows ファイアウォールが ICMP を弾いている可能性"
                ) `
                -Metrics ([PSCustomObject]@{ icmpStatus = $reply.Status.ToString(); arpResolved = [bool]($arp -and $arp.LinkLayerAddress) })
        }
    } catch {
        Add-Result -Step "ゲートウェイ ping" -Layer "L3-local" -Status "fail" `
            -Detail "ping エラー: $_" `
            -Hints @("ICMP 送信エラー、Windows ファイアウォールを確認")
    } finally {
        $ping.Dispose()
    }

    $gatewayQualityStats = Invoke-PingSeries -Target $gw -Count $LocalPingSamples -TimeoutMs $PingTimeoutMs
    $gwQualityStatus = Get-PingQualityStatus -Stats $gatewayQualityStats -Scope 'local'
    if ($gwQualityStatus -eq 'fail' -and $arp -and $arp.LinkLayerAddress) {
        $gwQualityStatus = 'warn'
    }

    $gwHints = @()
    if ($gwQualityStatus -ne 'pass') {
        if ($primaryAdapterKind -eq 'wifi') {
            $gwHints += "ゲートウェイへの遅延/損失が悪い場合、インターネット以前に Wi-Fi/AP/ルーター間で詰まっています"
            $gwHints += "有線では安定するなら、Wi-Fi 電波・干渉・AP負荷・子機ドライバが主な候補です"
            Add-Finding -Severity 'high' -Area 'Wi-Fi/AP' `
                -Reason 'ルーターまでのローカル通信が不安定' `
                -Evidence (Format-PingStats $gatewayQualityStats) `
                -Action 'APの近くで再測定し、5GHz/6GHzまたは有線との差を比較してください'
        } else {
            $gwHints += "ゲートウェイへの遅延/損失が悪いため、LAN内のケーブル/スイッチ/ルーター負荷が疑われます"
            Add-Finding -Severity 'high' -Area 'LAN/ルーター' `
                -Reason 'ルーターまでのローカル通信が不安定' `
                -Evidence (Format-PingStats $gatewayQualityStats) `
                -Action 'ケーブル・スイッチ・ルーターの負荷/再起動を確認してください'
        }
    }

    Add-Result -Step "ゲートウェイ連続 ping" -Layer "L3-local quality" -Status $gwQualityStatus `
        -Detail (Format-PingStats $gatewayQualityStats) `
        -Evidence ("samples(ms): " + (($gatewayQualityStats.samples | ForEach-Object { [string]$_ }) -join ', ')) `
        -Hints $gwHints `
        -Metrics $gatewayQualityStats
}

# ======================================================================
# Step 5: 外部 IP 到達性
# ======================================================================
$internetReachable = $false
$internetQualityStats = @()
$bestInternetQuality = $null
$mtuProbe = $null
if ($NoExternalServices) {
    Add-Result -Step "インターネット IP 到達性" -Layer "L3-internet" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
} elseif ($gw) {
    Write-Host "`n--- Step 5: L3-internet (外部 IP 到達性) ---" -ForegroundColor Cyan

    $reachableCount = 0
    $details = @()
    foreach ($ext in $ExternalIps) {
        $ping = New-Object System.Net.NetworkInformation.Ping
        try {
            $reply = $ping.Send($ext, $PingTimeoutMs)
            if ($reply.Status -eq 'Success') {
                $reachableCount++
                $details += "$ext OK ($($reply.RoundtripTime) ms)"
            } else {
                $details += "$ext NG ($($reply.Status))"
            }
        } catch {
            $details += "$ext ERROR"
        } finally {
            $ping.Dispose()
        }
    }

    if ($reachableCount -gt 0) {
        $internetReachable = $true
        Add-Result -Step "インターネット IP 到達性" -Layer "L3-internet" -Status "pass" `
            -Detail "$reachableCount / $($ExternalIps.Count) の外部 IP に到達" `
            -Evidence ($details -join '; ')
    } else {
        $hintList = @(
            "ルーターから先 (ISP/インターネット) への通信ができていない",
            "ONU/モデムの電源を入れ直す (1分ほど待ってから戻す)",
            "ルーターの WAN 側ステータスを管理画面で確認",
            "PPPoE 接続の場合: ID/パスワードを再確認",
            "ISP の障害情報を確認 (ISP公式サイト/Twitter等)",
            "tracert 8.8.8.8 でどのホップで止まるか確認"
        )
        if (-not $gwReachable) {
            $hintList = @("先のステップでゲートウェイへの到達に失敗しています。先にそちらを解決してください") + $hintList
        } else {
            Add-Finding -Severity 'high' -Area 'WAN/ISP' `
                -Reason '外部IPに到達できない' `
                -Evidence ($details -join '; ') `
                -Action 'ONU/モデム/ルーターWAN状態、PPPoE設定、ISP障害を確認してください'
        }
        Add-Result -Step "インターネット IP 到達性" -Layer "L3-internet" -Status "fail" `
            -Detail "外部 IP に1つも到達できません" `
            -Evidence ($details -join '; ') -Hints $hintList
    }
} else {
    Add-Result -Step "インターネット IP 到達性" -Layer "L3-internet" -Status "skip" `
        -Detail "ゲートウェイ未設定のためスキップ"
}

# ======================================================================
# Step 5.5: インターネット遅延/損失 + MTU
# ======================================================================
if ($gw -and $internetReachable) {
    Write-Host "`n--- Step 5.5: L3品質 (外部遅延/損失/MTU) ---" -ForegroundColor Cyan

    foreach ($ext in $ExternalIps) {
        $internetQualityStats += Invoke-PingSeries -Target $ext -Count $InternetPingSamples -TimeoutMs $PingTimeoutMs
    }

    $bestInternetQuality = $internetQualityStats | Sort-Object lossPct, avgMs | Select-Object -First 1
    $inetQualityStatus = Get-PingQualityStatus -Stats $bestInternetQuality -Scope 'internet'
    $inetHints = @()

    if ($inetQualityStatus -ne 'pass') {
        if ($gatewayQualityStats -and (Get-PingQualityStatus -Stats $gatewayQualityStats -Scope 'local') -eq 'pass') {
            $inetHints += "ゲートウェイまでは安定している一方、外部IPへの遅延/損失が悪いため、ルーターWAN側/ONU/ISP/経路混雑が疑われます"
            Add-Finding -Severity 'high' -Area 'WAN/ISP' `
                -Reason 'LAN内は安定しているが外部通信が不安定' `
                -Evidence (Format-PingStats $bestInternetQuality) `
                -Action 'ONU/ルーターのWAN状態、ISP障害情報、混雑時間帯の再測定を確認してください'
        } else {
            $inetHints += "外部IPの品質が悪いですが、先にゲートウェイまでの品質も確認してください"
        }
        $inetHints += "夜だけ悪い場合は ISP/回線混雑、常時悪い場合はルーター/ONU/回線品質の可能性が高くなります"
    }

    Add-Result -Step "インターネット遅延・損失" -Layer "L3-internet quality" -Status $inetQualityStatus `
        -Detail (Format-PingStats $bestInternetQuality) `
        -Evidence (@($internetQualityStats | ForEach-Object { Format-PingStats $_ }) -join ' | ') `
        -Hints $inetHints `
        -Metrics ([PSCustomObject]@{
            bestTarget = $bestInternetQuality.target
            targets    = @($internetQualityStats)
        })

    $mtuTarget = $bestInternetQuality.target
    if ($mtuTarget) {
        $mtuProbe = Test-MtuProbe -Target $mtuTarget -TimeoutMs $PingTimeoutMs
        $mtuStatus = 'pass'
        $mtuHints = @()
        $probeText = (@($mtuProbe.probes | ForEach-Object {
            $resultText = if ($_.ok) { 'OK' } else { 'NG' }
            "$($_.payloadBytes)=$resultText"
        }) -join '; ')

        if ($null -eq $mtuProbe.maxPayload) {
            $mtuStatus = 'warn'
            $mtuHints += "DFビット付き ping が全て失敗しました。ICMPブロックの可能性もあるため、MTUだけでは断定できません"
        } elseif ($mtuProbe.maxPayload -lt 1472) {
            $mtuHints += "経路MTUは $($mtuProbe.estimatedMtu) bytes です$(if ($mtuProbe.pathType) { "（代表値との一致から $($mtuProbe.pathType) の可能性）" })。トンネル/PPPoE 経路では正常な値で、それ自体は問題ではありません"
        }

        # NIC 側の MTU 設定が経路MTUより大きいと、DF付き大パケットが黙って落ちる
        # 「PMTUDブラックホール」の素地になる（ping は通るのに特定サイトだけ固まる症状）
        if ($mtuProbe.estimatedMtu -and $primaryAdapter) {
            $ifMtu = $null
            try {
                $nlIf = Get-NetIPInterface -InterfaceIndex $primaryAdapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop
                if ($nlIf) { $ifMtu = [int]$nlIf.NlMtu }
            } catch { }
            if ($ifMtu) {
                # トンネル/PPPoE 環境では NIC=1500 > 経路MTU が常態で、PMTUD が自動調整する。
                # 差が 100 を超える(VPN の設定ミス等)場合だけ警告し、それ以外は情報として示す
                $mtuGap = $ifMtu - $mtuProbe.estimatedMtu
                if ($mtuGap -gt 100) {
                    $mtuStatus = 'warn'
                    $mtuHints += "NIC の MTU 設定($ifMtu)が経路MTU($($mtuProbe.estimatedMtu))を大きく上回っています。経路上で ICMP が止められていると『ping は通るのに特定サイトの読み込みだけ固まる』症状(PMTUDブラックホール)になります"
                    Add-Finding -Severity 'medium' -Area 'MTU' `
                        -Reason 'NICのMTU設定と実測の経路MTUの差が大きい（ブラックホールの素地）' `
                        -Evidence "interface MTU=$ifMtu > path MTU=$($mtuProbe.estimatedMtu) ($probeText)" `
                        -Action "症状がある場合のみ、管理者PowerShellで: Set-NetIPInterface -InterfaceIndex $($primaryAdapter.ifIndex) -NlMtuBytes $($mtuProbe.estimatedMtu)"
                } elseif ($mtuGap -gt 0) {
                    $mtuHints += "NIC の MTU($ifMtu)は経路MTU($($mtuProbe.estimatedMtu))より大きいですが、この程度の差は PMTUD が自動調整するのが普通です。特定サイトだけ固まる症状が出た時だけ MTU を疑ってください"
                } else {
                    $mtuHints += "NIC の MTU 設定($ifMtu)は経路MTU($($mtuProbe.estimatedMtu))と整合しています"
                }
            }
        }

        $mtuDetail = if ($mtuProbe.estimatedMtu) {
            "経路MTU=$($mtuProbe.estimatedMtu) bytes$(if ($mtuProbe.pathType) { " [$($mtuProbe.pathType)]" })"
        } else {
            "推定不可 ($probeText)"
        }
        Add-Result -Step "MTU 簡易チェック" -Layer "L3/PMTUD" -Status $mtuStatus `
            -Detail $mtuDetail `
            -Evidence "target=$($mtuProbe.target); payload probes: $probeText" `
            -Hints $mtuHints `
            -Metrics $mtuProbe
    }
} elseif ($NoExternalServices) {
    Add-Result -Step "インターネット遅延・損失" -Layer "L3-internet quality" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
    Add-Result -Step "MTU 簡易チェック" -Layer "L3/PMTUD" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
} elseif ($gw) {
    Add-Result -Step "インターネット遅延・損失" -Layer "L3-internet quality" -Status "skip" `
        -Detail "外部IP到達性がないため品質測定をスキップ"
    Add-Result -Step "MTU 簡易チェック" -Layer "L3/PMTUD" -Status "skip" `
        -Detail "外部IP到達性がないためスキップ"
}

# ======================================================================
# Step 5.7: 二重NAT検出 (経路上に複数のNAT)
# ======================================================================
if ($gw -and $internetReachable -and (Test-PrivateIp $gw)) {
    Write-Host "`n--- Step 5.7: L3-routing (二重NAT/CGN検出) ---" -ForegroundColor Cyan
    $hops = Get-FirstHops -Target ($ExternalIps | Select-Object -First 1) -MaxHops 4
    $script:firstHops = @($hops)   # Step 8 の負荷時ホップ別測定で再利用
    # GW以降の私的IPホップを、宅内のもう一段のNAT(RFC1918)と
    # キャリア網の共有アドレス(CGN: 100.64/10)に分けて評価する。
    # CGN は DS-Lite/MAP-E/キャリアNAT で正常な構成であり、二重NATの警告を出すと誤診になる
    $beyondGw   = @($hops | Where-Object { $_.hop -ge 2 -and (Test-PrivateIp $_.ip) -and $_.ip -ne $gw })
    $cgnHops    = @($beyondGw | Where-Object { Test-CgnIp $_.ip })
    $privateBeyondGw = @($beyondGw | Where-Object { $cgnHops -notcontains $_ })
    $hopText = (@($hops | ForEach-Object { "h$($_.hop)=$($_.ip)" }) -join ' ')

    # 外部から見た自分の IPv4（NAT/CGN の最終出口）。取得失敗しても診断は続行
    $externalIp = $null
    try {
        $externalIp = [string](Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 4 -ErrorAction Stop)
        if ($externalIp -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { $externalIp = $null }
    } catch { }
    $extText = if ($externalIp) { "外部IP=$externalIp" } else { "外部IP取得不可" }

    # 機器調査(UPnP)で取れたルータの WAN 側 IP があれば照合する。
    # WAN 側がプライベート/共有アドレスなら、tracert が拾えなくても上流NATが確定する。
    # network-data.json は前回実行の成果物（診断→収集の順で走るため）なので、
    # 「同じゲートウェイについての、新しい記録」のときだけ使う。
    # 構成変更後に古い WAN 情報で誤判定するのを防ぐ
    $routerWanIp = $null
    try {
        $ndPath = Join-Path (Split-Path -Parent $OutputPath) 'network-data.json'
        if (Test-Path $ndPath) {
            $nd = Get-Content $ndPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($nd.wanInfo -and $nd.wanInfo.externalIp -and
                "$($nd.wanInfo.routerIp)" -eq "$gw" -and
                $nd.wanInfo.fetchedAt -and
                ((Get-Date) - [datetime]$nd.wanInfo.fetchedAt).TotalHours -lt 24) {
                $routerWanIp = [string]$nd.wanInfo.externalIp
            }
        }
    } catch { }
    $routerWanIsCgn     = ($routerWanIp -and (Test-CgnIp $routerWanIp))
    $routerWanIsPrivate = ($routerWanIp -and -not $routerWanIsCgn -and (Test-PrivateIp $routerWanIp))
    if ($routerWanIp) { $extText += "; ルータWAN側=$routerWanIp" }

    if ($privateBeyondGw.Count -ge 1 -or $routerWanIsPrivate) {
        Add-Finding -Severity 'medium' -Area '二重NAT' `
            -Reason 'ゲートウェイの先にもう一段プライベートIPのルータがある（二重NATの可能性）' `
            -Evidence "gateway=$gw; hops: $hopText; $extText" `
            -Action 'ルータを1台だけNATにする（片方をブリッジ/APモードに）と、ポート開放・オンラインゲーム・VPNの不調が改善する場合があります'
        $dnDetail = if ($privateBeyondGw.Count -ge 1) {
            "二重NATの可能性: GWの先にも私的IPルータ ($($privateBeyondGw[0].ip))"
        } else {
            "二重NATの可能性: ルータのWAN側がプライベートIP ($routerWanIp)"
        }
        Add-Result -Step "二重NAT検出" -Layer "L3-routing" -Status "warn" `
            -Detail $dnDetail `
            -Evidence "hops: $hopText; $extText" `
            -Hints @(
                "ルータが2台直列(回線終端装置/ONU内蔵ルータ + 市販ルータ等)になっていないか確認",
                "市販ルータをブリッジ(AP)モードにする、または上位機器のルータ機能を切る",
                "二重NATでもWeb閲覧は可能だが、ポート開放/UPnP/一部ゲーム/VPNで問題が出やすい"
            ) `
            -Metrics ([PSCustomObject]@{ gateway = $gw; hops = @($hops); externalIp = $externalIp; routerWanIp = $routerWanIp; cgn = $false })
    } elseif ($cgnHops.Count -ge 1 -or $routerWanIsCgn) {
        $cgnSeen = if ($cgnHops.Count -ge 1) { $cgnHops[0].ip } else { $routerWanIp }
        Add-Result -Step "二重NAT検出" -Layer "L3-routing" -Status "pass" `
            -Detail "キャリア網の共有アドレス(CGN)を検出: $cgnSeen（ISP側でアドレスを共有する正常な構成）" `
            -Evidence "hops: $hopText; $extText" `
            -Hints @(
                "宅内の二重NATではなく、ISP側でアドレスを共有する方式(CGN)です。設定変更は不要です",
                "この方式ではポート開放・自宅サーバ公開は原則できません。必要なら固定IPオプションや PPPoE 併用を検討してください"
            ) `
            -Metrics ([PSCustomObject]@{ gateway = $gw; hops = @($hops); externalIp = $externalIp; routerWanIp = $routerWanIp; cgn = $true })
    } else {
        Add-Result -Step "二重NAT検出" -Layer "L3-routing" -Status "pass" `
            -Detail "二重NATは検出されませんでした$(if ($externalIp) { "（$extText）" })" `
            -Evidence "hops: $hopText; $extText" `
            -Metrics ([PSCustomObject]@{ gateway = $gw; hops = @($hops); externalIp = $externalIp; routerWanIp = $routerWanIp; cgn = $false })
    }
}

# ======================================================================
# Step 5.8: IPv4 vs IPv6 経路比較
#   日本の回線では v4(PPPoE) と v6(IPoE) で物理的に別経路を通ることが多く、
#   夜間の「v4 だけ遅い」は PPPoE 網終端装置の混雑が典型。
#   同一事業者の v4/v6 アンカーへの RTT 差で経路差を可視化する
# ======================================================================
if ($gw -and $internetReachable) {
    Write-Host "`n--- Step 5.8: L3 (IPv4 vs IPv6 経路比較) ---" -ForegroundColor Cyan
    $famPairs = @(
        [PSCustomObject]@{ name = 'Cloudflare'; v4 = '1.1.1.1'; v6 = '2606:4700:4700::1111' }
        [PSCustomObject]@{ name = 'Google';     v4 = '8.8.8.8'; v6 = '2001:4860:4860::8888' }
    )
    $famRows = @()
    foreach ($p in $famPairs) {
        $s4 = Invoke-PingSeries -Target $p.v4 -Count 8 -TimeoutMs $PingTimeoutMs
        $s6 = Invoke-PingSeries -Target $p.v6 -Count 8 -TimeoutMs $PingTimeoutMs
        $famRows += [PSCustomObject]@{
            name     = $p.name
            v4AvgMs  = $s4.avgMs
            v4LossPct = $s4.lossPct
            v6AvgMs  = $s6.avgMs
            v6LossPct = $s6.lossPct
            diffMs   = if ($null -ne $s4.avgMs -and $null -ne $s6.avgMs) { [math]::Round($s4.avgMs - $s6.avgMs, 1) } else { $null }
        }
    }
    $v6Alive = @($famRows | Where-Object { $null -ne $_.v6AvgMs })
    if ($v6Alive.Count -eq 0) {
        Add-Result -Step "IPv4/IPv6 経路比較" -Layer "L3-internet" -Status "skip" `
            -Detail "IPv6 での外部到達ができないため比較なし（IPv4 のみの環境）" `
            -Metrics ([PSCustomObject]@{ pairs = @($famRows) })
    } else {
        $famStatus = 'pass'; $famHints = @()
        # 両ファミリで値が取れたペアの平均差（正= v4 が遅い）
        $validDiffs = @($famRows | Where-Object { $null -ne $_.diffMs } | ForEach-Object { $_.diffMs })
        $avgDiff = if ($validDiffs.Count -gt 0) { [math]::Round((($validDiffs | Measure-Object -Average).Average), 1) } else { $null }
        if ($null -ne $avgDiff -and $avgDiff -ge 15) {
            $famStatus = 'warn'
            $famHints += "IPv4 の方が平均 +$avgDiff ms 遅く、v4/v6 で経路品質に差があります。IPv4 と IPv6 が別経路になる契約では、IPv4 側の ISP 設備の混雑が典型原因です"
            $famHints += "IPv4 通信も IPv6 経路へ通す方式(IPv4 over IPv6: DS-Lite / MAP-E 等)が使える回線なら、切り替えで v4 も改善する見込みがあります"
            Add-Finding -Severity 'medium' -Area 'v4/v6経路' `
                -Reason 'IPv4 経路が IPv6 経路より有意に遅い（接続方式による経路差の可能性）' `
                -Evidence (@($famRows | ForEach-Object { "$($_.name): v4=$($_.v4AvgMs)ms v6=$($_.v6AvgMs)ms" }) -join '; ') `
                -Action 'ISP の IPv4 over IPv6 オプション(DS-Lite/MAP-E)の利用状況を確認してください。夜間だけ差が開くなら PPPoE 混雑がほぼ確定です'
        } elseif ($null -ne $avgDiff -and $avgDiff -le -15) {
            $famStatus = 'warn'
            $famHints += "IPv6 の方が平均 $([math]::Abs($avgDiff)) ms 遅い状態です。v6 経路(トンネルや網内経路)の問題か、ルータの v6 処理性能の可能性があります"
        } elseif ($null -ne $avgDiff) {
            $famHints += "IPv4 と IPv6 の遅延差は $avgDiff ms で、経路品質に大きな差はありません"
        }
        $famDetail = (@($famRows | ForEach-Object {
            "$($_.name): v4=$(if ($null -ne $_.v4AvgMs) { "$($_.v4AvgMs)ms" } else { '-' }) / v6=$(if ($null -ne $_.v6AvgMs) { "$($_.v6AvgMs)ms" } else { '-' })"
        }) -join ' | ')
        Add-Result -Step "IPv4/IPv6 経路比較" -Layer "L3-internet" -Status $famStatus `
            -Detail $famDetail `
            -Evidence "各8回ping の平均。正の差= v4 が遅い" `
            -Hints $famHints `
            -Metrics ([PSCustomObject]@{ pairs = @($famRows); avgDiffMs = $avgDiff })
    }
}

# ======================================================================
# Step 5.9: 経路の重複（複数のデフォルトゲートウェイ）
#   有線と Wi-Fi を同時に繋いでいると、デフォルトルートが 2 本になる。
#   Windows はインターフェイスメトリックの小さい方を先に使うが、
#   そちらが実際には通じていないと、通信のたびにタイムアウト待ちが発生する。
#   DNS が「たまに異常に遅い」の典型的な原因。
# ======================================================================
Write-Host "`n--- Step 5.9: L3-routing (経路の重複) ---" -ForegroundColor Cyan
$gatewayInventory = @()
try {
    $ifMetrics = @{}
    foreach ($ni in @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.ConnectionState -eq 'Connected' })) {
        $ifMetrics[[int]$ni.ifIndex] = @{ alias = [string]$ni.InterfaceAlias; metric = [int]$ni.InterfaceMetric }
    }
    $defRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                   Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
    foreach ($r in $defRoutes) {
        $info = $ifMetrics[[int]$r.ifIndex]
        $alias = if ($info) { $info.alias } else { [string]$r.InterfaceAlias }
        $metric = if ($info) { $info.metric } else { $null }
        # 実際に到達できるゲートウェイかどうかを確かめる
        $alive = $false
        try { $alive = (New-Object System.Net.NetworkInformation.Ping).Send([string]$r.NextHop, $PingTimeoutMs).Status -eq 'Success' } catch { }
        $gatewayInventory += [PSCustomObject]@{
            gateway         = [string]$r.NextHop
            interfaceAlias  = $alias
            interfaceMetric = $metric
            routeMetric     = [int]$r.RouteMetric
            reachable       = $alive
        }
    }
} catch { }

if ($gatewayInventory.Count -gt 1) {
    # Windows が優先するのはインターフェイスメトリックの小さい方
    $ordered  = @($gatewayInventory | Sort-Object interfaceMetric, routeMetric)
    $preferred = $ordered[0]
    $listText = (@($ordered | ForEach-Object {
        "$($_.interfaceAlias)=$($_.gateway)(metric $($_.interfaceMetric), $(if ($_.reachable) { '到達可' } else { '到達不可' }))"
    }) -join ' | ')

    if (-not $preferred.reachable) {
        # 最優先の経路が死んでいる = すべての通信が毎回タイムアウト待ちになる
        Add-Finding -Severity 'high' -Area '経路の重複' `
            -Reason 'Windows が優先する経路のゲートウェイに到達できない（通信のたびにタイムアウト待ちが起きる）' `
            -Evidence $listText `
            -Action "$($preferred.interfaceAlias) のデフォルトゲートウェイ設定を外すか、そのインターフェイスのメトリックを大きくして優先順位を下げてください"
        Add-Result -Step "経路の重複" -Layer "L3-routing" -Status "fail" `
            -Detail "デフォルトゲートウェイが $($gatewayInventory.Count) 個あり、優先される $($preferred.interfaceAlias) ($($preferred.gateway)) に到達できません" `
            -Evidence $listText `
            -Hints @(
                "Windows はインターフェイスメトリックが小さい経路を先に使います。そこが通じないと、毎回タイムアウトを待ってから別経路に切り替わります",
                "使わない方のインターフェイスで『デフォルトゲートウェイ』と『DNS サーバー』を空欄にしてください",
                "DHCP から配布される場合は、そのインターフェイスのメトリックを手動で大きくする方法もあります: Set-NetIPInterface -InterfaceAlias '$($preferred.interfaceAlias)' -InterfaceMetric 9999"
            ) `
            -Metrics ([PSCustomObject]@{ gateways = @($gatewayInventory); preferred = $preferred.gateway })
    } else {
        Add-Result -Step "経路の重複" -Layer "L3-routing" -Status "warn" `
            -Detail "デフォルトゲートウェイが $($gatewayInventory.Count) 個あります（優先: $($preferred.interfaceAlias) / $($preferred.gateway)）" `
            -Evidence $listText `
            -Hints @(
                "どちらの回線を使うかが状況で変わり、速度や遅延が実行ごとにばらつく原因になります",
                "インターネットに使う方だけにデフォルトゲートウェイを設定し、もう一方は空欄にすると挙動が安定します"
            ) `
            -Metrics ([PSCustomObject]@{ gateways = @($gatewayInventory); preferred = $preferred.gateway })
    }
} elseif ($gatewayInventory.Count -eq 1) {
    Add-Result -Step "経路の重複" -Layer "L3-routing" -Status "pass" `
        -Detail "デフォルトゲートウェイは 1 つです ($($gatewayInventory[0].gateway))"
}

# ======================================================================
# Step 6: DNS 名前解決
# ======================================================================
if ($NoExternalServices) {
    Add-Result -Step "DNS 名前解決" -Layer "DNS" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
    Add-Result -Step "HTTPS 接続 (443)" -Layer "Application" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
    Add-Result -Step "HTTPタイミング分解" -Layer "Application" -Status "skip" `
        -Detail "外部サービスへの通信を無効にしているため省略"
} else {
Write-Host "`n--- Step 6: DNS (名前解決) ---" -ForegroundColor Cyan

# 設定されている DNS サーバを「全インターフェイス」から集める。
# 主アダプタの分だけ見ていると、別アダプタに設定された応答しないサーバを
# 見落とす。Windows はメトリックの小さいインターフェイスの DNS を先に試すため、
# そこが死んでいると名前解決のたびにタイムアウト待ちになる。
$dnsInventory = @()
try {
    foreach ($ni in @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.ConnectionState -eq 'Connected' } | Sort-Object InterfaceMetric)) {
        $srv = @((Get-DnsClientServerAddress -InterfaceIndex $ni.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
                 Where-Object { $_ })
        foreach ($s in $srv) {
            $dnsInventory += [PSCustomObject]@{
                server          = [string]$s
                interfaceAlias  = [string]$ni.InterfaceAlias
                interfaceMetric = [int]$ni.InterfaceMetric
            }
        }
    }
} catch { }

$dnsServers = @($dnsInventory | ForEach-Object { $_.server } | Select-Object -Unique)
if ($dnsServers.Count -eq 0 -and $primaryConfig -and $primaryConfig.DNSServer) {
    $dnsServers = @($primaryConfig.DNSServer | Where-Object { $_.AddressFamily -eq 2 } |
                    ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
}

# --- DNSサーバ個別レイテンシ計測（設定中の各サーバを比較） ---
$dnsServerProbe = @()
# DNSサーバが1つも検出できなくても後段(名前解決の評価)で参照するため、ここで初期化
$reachable = @()
$unreach   = @()
if ($dnsServers.Count -gt 0) {
    $probeHost = if ($DnsTestHosts.Count -gt 0) { $DnsTestHosts[0] } else { 'www.google.com' }
    foreach ($ds in ($dnsServers | Select-Object -Unique)) {
        $okCount = 0; $msList = @()
        foreach ($i in 1..2) {
            try {
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $rr = Resolve-DnsName -Name $probeHost -Type A -Server $ds -QuickTimeout -DnsOnly -ErrorAction Stop |
                      Where-Object { $_.IPAddress } | Select-Object -First 1
                $sw.Stop()
                if ($rr) { $okCount++; $msList += [double]$sw.ElapsedMilliseconds }
            } catch { }
        }
        $avgMs = if ($msList.Count -gt 0) { [math]::Round((($msList | Measure-Object -Average).Average), 1) } else { $null }
        $inv = @($dnsInventory | Where-Object { $_.server -eq $ds })[0]
        $dnsServerProbe += [PSCustomObject]@{
            server          = $ds
            reachable       = ($okCount -gt 0)
            avgMs           = $avgMs
            interfaceAlias  = if ($inv) { $inv.interfaceAlias } else { $null }
            interfaceMetric = if ($inv) { $inv.interfaceMetric } else { $null }
        }
    }
    # 最遅/到達不可サーバを指摘
    $reachable = @($dnsServerProbe | Where-Object { $_.reachable -and $null -ne $_.avgMs })
    $unreach   = @($dnsServerProbe | Where-Object { -not $_.reachable })

    # Windows はインターフェイスメトリックの小さい方の DNS を先に試す。
    # そこが応答しないと、すべての名前解決がタイムアウト待ちになってから
    # 別のサーバへ切り替わる。サーバ単体が速くても体感は数秒遅くなる。
    $firstTried = @($dnsServerProbe | Where-Object { $null -ne $_.interfaceMetric } | Sort-Object interfaceMetric)[0]
    if ($firstTried -and -not $firstTried.reachable -and $reachable.Count -gt 0) {
        $fastest = @($reachable | Sort-Object avgMs)[0]
        Add-Finding -Severity 'high' -Area 'DNS' `
            -Reason 'Windows が最初に問い合わせる DNS サーバが応答しないため、名前解決のたびにタイムアウト待ちが発生している' `
            -Evidence "最初に試すサーバ=$($firstTried.server)（$($firstTried.interfaceAlias) / metric $($firstTried.interfaceMetric)）は無応答。応答するサーバ $($fastest.server) は $($fastest.avgMs) ms" `
            -Action "$($firstTried.interfaceAlias) の DNS サーバー設定を空欄にしてください（Set-DnsClientServerAddress -InterfaceAlias '$($firstTried.interfaceAlias)' -ResetServerAddresses）。DHCP で再配布される場合はそのインターフェイスのメトリックを上げてください"
    } elseif ($unreach.Count -gt 0 -and $reachable.Count -gt 0) {
        Add-Finding -Severity 'low' -Area 'DNS' `
            -Reason '設定中のDNSサーバの一部が応答しない' `
            -Evidence ("応答なし: " + (($unreach | ForEach-Object { $_.server }) -join ', ')) `
            -Action '応答するサーバのみ残すか、公共DNS(1.1.1.1/8.8.8.8)を併用してください'
    }
    if ($reachable.Count -ge 2) {
        $slow = $reachable | Sort-Object avgMs -Descending | Select-Object -First 1
        $fast = $reachable | Sort-Object avgMs | Select-Object -First 1
        if ($slow.avgMs -ge 200 -and $slow.avgMs -ge ($fast.avgMs * 3 + 50)) {
            Add-Finding -Severity 'low' -Area 'DNS' `
                -Reason '特定のDNSサーバだけ著しく遅い' `
                -Evidence "$($slow.server)=$($slow.avgMs)ms vs $($fast.server)=$($fast.avgMs)ms" `
                -Action "速い側($($fast.server))を優先DNSにする/遅い側を外すことを検討してください"
        }
    }
}

$resolvedCount = 0
$resolvedDetails = @()
$dnsTimes = @()
$appDnsTimes = @()
foreach ($targetHost in $DnsTestHosts) {
    # キャッシュに残っていると 0ms になり、実際の遅さが見えない
    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }

    # アプリが実際に使う経路（.NET の名前解決）も測る。
    # Resolve-DnsName -QuickTimeout より待ち時間が長いため、
    # 体感に近いのはこちら
    try {
        $swApp = [System.Diagnostics.Stopwatch]::StartNew()
        [void][System.Net.Dns]::GetHostAddresses($targetHost)
        $swApp.Stop()
        $appDnsTimes += [double]$swApp.ElapsedMilliseconds
    } catch { }

    try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch { }
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = Resolve-DnsName -Name $targetHost -Type A -QuickTimeout -DnsOnly -ErrorAction Stop |
             Where-Object { $_.IPAddress } | Select-Object -First 1
        $sw.Stop()
        if ($r -and $r.IPAddress) {
            $resolvedCount++
            $dnsTimes += [double]$sw.ElapsedMilliseconds
            $resolvedDetails += "$targetHost -> $($r.IPAddress) ($($sw.ElapsedMilliseconds) ms)"
        } else {
            $resolvedDetails += "$targetHost : 応答あるが A レコードなし ($($sw.ElapsedMilliseconds) ms)"
        }
    } catch {
        $resolvedDetails += "$targetHost : 解決失敗"
    }
}

if ($resolvedCount -gt 0) {
    $dnsMetric = $null
    $dnsStatus = 'pass'
    $dnsHints = @()
    if ($dnsTimes.Count -gt 0) {
        $dnsMeasure = $dnsTimes | Measure-Object -Minimum -Maximum -Average
        $appAvg = if ($appDnsTimes.Count -gt 0) { [math]::Round((($appDnsTimes | Measure-Object -Average).Average), 1) } else { $null }
        $bestServerMs = if ($reachable.Count -gt 0) { (@($reachable | Sort-Object avgMs)[0]).avgMs } else { $null }

        $dnsMetric = [PSCustomObject]@{
            resolved      = $resolvedCount
            total         = $DnsTestHosts.Count
            minMs         = [math]::Round([double]$dnsMeasure.Minimum, 1)
            avgMs         = [math]::Round([double]$dnsMeasure.Average, 1)
            maxMs         = [math]::Round([double]$dnsMeasure.Maximum, 1)
            appAvgMs      = $appAvg          # アプリが体感する時間
            bestServerMs  = $bestServerMs    # サーバ単体の速さ
        }
        if ($resolvedCount -lt $DnsTestHosts.Count -or $dnsMetric.avgMs -gt 500 -or $dnsMetric.maxMs -gt 1200) {
            $dnsStatus = 'warn'

            # サーバ単体は速いのにシステム経由が遅い＝サーバの性能ではなく
            # 「応答しないサーバを先に試している」など問い合わせ順の問題。
            # ここを区別しないと、DNS を変えても直らない対処に誘導してしまう。
            if ($null -ne $bestServerMs -and $bestServerMs -lt 100 -and $dnsMetric.avgMs -gt ($bestServerMs * 10)) {
                $dnsHints += "DNS サーバ自体は $bestServerMs ms で応答しています。にもかかわらず Windows 経由の名前解決に平均 $($dnsMetric.avgMs) ms かかっているため、遅いのは DNS サーバの性能ではなく『応答しないサーバを先に問い合わせて待っている』ことが原因です"
                $dnsHints += "DNS を公共DNSに変えても、応答しないサーバが設定に残っている限り改善しません。まず不要な DNS 設定を外してください"
                Add-Finding -Severity 'high' -Area 'DNS' `
                    -Reason 'DNS サーバ自体は速いが、システム経由の名前解決だけが極端に遅い（問い合わせ順の問題）' `
                    -Evidence "サーバ単体=$bestServerMs ms / システム経由=$($dnsMetric.avgMs) ms$(if ($appAvg) { " / アプリ体感=$appAvg ms" })" `
                    -Action '応答しない DNS サーバが設定されているインターフェイスで、DNS 設定を空欄にしてください'
            } else {
                $dnsHints += "DNS は解決できていますが、遅い/一部失敗しています。Webページが開き始めるまで遅い症状の原因になります"
                $dnsHints += "ルーター配布DNS、ISP DNS、セキュリティソフトのDNSフィルタ、IPv6 DNS設定を確認してください"
                Add-Finding -Severity 'medium' -Area 'DNS' `
                    -Reason 'DNS の応答が遅い、または一部失敗している' `
                    -Evidence "resolved=$resolvedCount/$($DnsTestHosts.Count), avg=$($dnsMetric.avgMs) ms, max=$($dnsMetric.maxMs) ms" `
                    -Action '一時的に 1.1.1.1 / 8.8.8.8 などで比較し、改善するか確認してください'
            }
            if ($appAvg -and $appAvg -gt $dnsMetric.avgMs * 1.3) {
                $dnsHints += "アプリが実際に待つ時間は平均 $appAvg ms で、診断コマンド経由よりさらに長くなっています（アプリ側は待ち時間の上限が長いため）"
            }
        }
    }
    $perServerText = ""
    if ($dnsServerProbe.Count -gt 0) {
        # どのインターフェイス由来かを併記する。応答しないサーバがどこに
        # 設定されているか分からないと直しようがない
        $perServerText = "; perServer: " + (($dnsServerProbe | ForEach-Object {
            $whereText = if ($_.interfaceAlias) { "@$($_.interfaceAlias)/metric$($_.interfaceMetric)" } else { "" }
            if ($_.reachable) { "$($_.server)$whereText=$($_.avgMs)ms" } else { "$($_.server)$whereText=応答なし" }
        }) -join ', ')
    }
    $dnsMetricsOut = [PSCustomObject]@{
        resolved     = $resolvedCount
        total        = $DnsTestHosts.Count
        minMs        = if ($dnsMetric) { $dnsMetric.minMs } else { $null }
        avgMs        = if ($dnsMetric) { $dnsMetric.avgMs } else { $null }
        maxMs        = if ($dnsMetric) { $dnsMetric.maxMs } else { $null }
        appAvgMs     = if ($dnsMetric) { $dnsMetric.appAvgMs } else { $null }
        bestServerMs = if ($dnsMetric) { $dnsMetric.bestServerMs } else { $null }
        perServer    = @($dnsServerProbe)
        servers      = @($dnsServerProbe)
    }
    Add-Result -Step "DNS 名前解決" -Layer "DNS" -Status $dnsStatus `
        -Detail "$resolvedCount / $($DnsTestHosts.Count) 件のホスト名を解決" `
        -Evidence (($resolvedDetails -join '; ') + $perServerText) `
        -Hints $dnsHints `
        -Metrics $dnsMetricsOut
} else {
    $dnsList = if ($dnsServers.Count -gt 0) { $dnsServers -join ', ' } else { '(未設定)' }
    $hintList = @(
        "DNS サーバーに到達できないか、サーバー側の障害",
        "現在の DNS サーバー: $dnsList",
        "公共 DNS に変更して試す: 8.8.8.8 (Google), 1.1.1.1 (Cloudflare)",
        "コマンド: nslookup google.com 8.8.8.8 で公共 DNS を直接試す",
        "DHCP で配布された DNS が間違っている可能性"
    )
    if (-not $internetReachable) {
        $hintList = @("先のステップでインターネットに到達できていません。DNS が解決できないのは当然の結果です") + $hintList
    } else {
        Add-Finding -Severity 'high' -Area 'DNS' `
            -Reason 'DNS 名前解決が失敗している' `
            -Evidence ($resolvedDetails -join '; ') `
            -Action 'DNSサーバー設定を確認し、公共DNS指定で再測定してください'
    }
    Add-Result -Step "DNS 名前解決" -Layer "DNS" -Status "fail" `
        -Detail "ホスト名が解決できません" `
        -Evidence ($resolvedDetails -join '; ') -Hints $hintList
}

# ======================================================================
# Step 7: HTTPS 接続
# ======================================================================
Write-Host "`n--- Step 7: Application (HTTPS 接続) ---" -ForegroundColor Cyan
$httpsOk = 0
$httpsDetails = @()
$httpsTimes = @()
foreach ($targetHost in $HttpsTestHosts) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $task = $tcp.ConnectAsync($targetHost, 443)
        $completed = $task.Wait(2500)
        $sw.Stop()
        if ($completed -and $tcp.Connected) {
            $httpsOk++
            $httpsTimes += [double]$sw.ElapsedMilliseconds
            $httpsDetails += "${targetHost}:443 OK ($($sw.ElapsedMilliseconds) ms)"
            $tcp.Close()
        } else {
            $httpsDetails += "${targetHost}:443 タイムアウト/失敗 ($($sw.ElapsedMilliseconds) ms)"
            try { $tcp.Close() } catch { }
        }
    } catch {
        $httpsDetails += "${targetHost}:443 エラー"
    }
}

if ($httpsOk -gt 0) {
    $httpsStatus = 'pass'
    $httpsHints = @()
    $httpsMetric = $null
    if ($httpsTimes.Count -gt 0) {
        $httpsMeasure = $httpsTimes | Measure-Object -Minimum -Maximum -Average
        $httpsMetric = [PSCustomObject]@{
            connected = $httpsOk
            total     = $HttpsTestHosts.Count
            minMs     = [math]::Round([double]$httpsMeasure.Minimum, 1)
            avgMs     = [math]::Round([double]$httpsMeasure.Average, 1)
            maxMs     = [math]::Round([double]$httpsMeasure.Maximum, 1)
        }
        if ($httpsOk -lt $HttpsTestHosts.Count -or $httpsMetric.avgMs -gt 1200 -or $httpsMetric.maxMs -gt 2500) {
            $httpsStatus = 'warn'
            $httpsHints += "DNS/IP到達後の TCP/443 接続が遅い、または一部失敗しています。Webや動画の初期接続が詰まる原因になります"
            $httpsHints += "プロキシ、セキュリティソフト、SSL検査、ルーターのNATテーブル、IPv6/IPv4経路差を確認してください"
            Add-Finding -Severity 'medium' -Area 'HTTPS/TCP' `
                -Reason 'HTTPS 接続の確立が遅い、または一部失敗している' `
                -Evidence "connected=$httpsOk/$($HttpsTestHosts.Count), avg=$($httpsMetric.avgMs) ms, max=$($httpsMetric.maxMs) ms" `
                -Action 'セキュリティソフト/プロキシ/VPNを一時的に切り分け、別ブラウザや有線でも比較してください'
        }
    }
    Add-Result -Step "HTTPS 接続 (443)" -Layer "Application" -Status $httpsStatus `
        -Detail "$httpsOk / $($HttpsTestHosts.Count) のホストの 443 ポートに接続" `
        -Evidence ($httpsDetails -join '; ') `
        -Hints $httpsHints `
        -Metrics $httpsMetric
} else {
    Add-Finding -Severity 'high' -Area 'HTTPS/TCP' `
        -Reason 'HTTPS 接続が確立できない' `
        -Evidence ($httpsDetails -join '; ') `
        -Action 'ファイアウォール、プロキシ、SSL検査、VPN、IPv6/IPv4経路を確認してください'
    Add-Result -Step "HTTPS 接続 (443)" -Layer "Application" -Status "fail" `
        -Detail "HTTPS 接続できません" `
        -Evidence ($httpsDetails -join '; ') `
        -Hints @(
            "ファイアウォール/セキュリティソフトで 443 ポートがブロックされている",
            "企業ネットワークの場合、プロキシ経由でないと外部に出られない可能性",
            "SSL 検査製品により証明書検証が失敗している可能性",
            "DNS は解決できるが TCP 接続できない → 経路上の問題"
        )
}

# ======================================================================
# Step 7.5: HTTP タイミング分解（DNS / TCP接続 / TLS / TTFB）
#   「速度は出るのにブラウジングが重い」の切り分け。
#   TLS だけ突出して遅い場合はセキュリティソフトの TLS 検査(MITM)が典型
# ======================================================================
if ($internetReachable) {
    Write-Host "`n--- Step 7.5: Application (HTTPタイミング分解) ---" -ForegroundColor Cyan
    $timingHosts = @('www.google.com', 'www.yahoo.co.jp')
    $timingRows = @()
    foreach ($th in $timingHosts) {
        $timingRows += Measure-HttpTiming -TargetHost $th
    }
    $okRows = @($timingRows | Where-Object { $_.ok })
    if ($okRows.Count -eq 0) {
        Add-Result -Step "HTTPタイミング分解" -Layer "Application" -Status "skip" `
            -Detail "測定失敗（HTTPS 接続の項を確認してください）" `
            -Metrics ([PSCustomObject]@{ rows = @($timingRows) })
    } else {
        $htStatus = 'pass'; $htHints = @()
        $avgOf = { param($prop) [math]::Round((@($okRows | ForEach-Object { $_.$prop } | Where-Object { $null -ne $_ }) | Measure-Object -Average).Average, 1) }
        $aDns = & $avgOf 'dnsMs'; $aTcp = & $avgOf 'tcpMs'; $aTls = & $avgOf 'tlsMs'; $aTtfb = & $avgOf 'ttfbMs'

        # TLS はハンドシェイク往復ぶんで TCP 接続の 2〜3 倍かかるのが正常。
        # それを大きく超える場合、途中でセキュリティソフトが復号・再暗号化している疑い
        if ($null -ne $aTls -and $null -ne $aTcp -and $aTcp -gt 0 -and $aTls -ge 200 -and $aTls -ge ($aTcp * 6)) {
            $htStatus = 'warn'
            $htHints += "TLS ハンドシェイク($aTls ms)が TCP 接続($aTcp ms)に比べて突出して遅い状態です。セキュリティソフトの TLS 検査(HTTPSスキャン)が介在している可能性が高く、全サイトの表示開始が一律に遅くなります"
            Add-Finding -Severity 'medium' -Area 'HTTPS/TLS' `
                -Reason 'TLSハンドシェイクだけが突出して遅い（TLS検査ソフト介在の疑い）' `
                -Evidence "avg: dns=$aDns ms tcp=$aTcp ms tls=$aTls ms ttfb=$aTtfb ms" `
                -Action 'セキュリティソフトの「Webの保護/HTTPSスキャン」を一時的に無効化して比較してください。改善するならその機能が原因です'
        } elseif ($null -ne $aTtfb -and $null -ne $aTcp -and $aTtfb -ge 500 -and $aTcp -lt 100) {
            $htStatus = 'warn'
            $htHints += "接続は速いのに最初の応答(TTFB $aTtfb ms)が遅い状態です。経路の帯域ではなく、プロキシ/フィルタリング、または相手サーバ側の要因です"
        } else {
            $htHints += "各フェーズ(DNS $aDns / TCP $aTcp / TLS $aTls / TTFB $aTtfb ms)に異常な偏りはありません"
        }
        $htDetail = (@($okRows | ForEach-Object {
            "$($_.targetHost): DNS $($_.dnsMs) / TCP $($_.tcpMs) / TLS $($_.tlsMs) / TTFB $($_.ttfbMs) ms"
        }) -join ' | ')
        Add-Result -Step "HTTPタイミング分解" -Layer "Application" -Status $htStatus `
            -Detail $htDetail `
            -Evidence "HTTPS の 1 アクセスを DNS解決/TCP接続/TLSハンドシェイク/最初の応答(TTFB) に分解して実測" `
            -Hints $htHints `
            -Metrics ([PSCustomObject]@{ rows = @($timingRows); avgDnsMs = $aDns; avgTcpMs = $aTcp; avgTlsMs = $aTls; avgTtfbMs = $aTtfb })
    }
}
}

# ======================================================================
# Step 8: 実効スループット測定（-SpeedTest 指定時のみ。能動・データ通信あり）
#   速度を実測し、リンク速度・Step 2.3 の設定所見と相関させて原因を特定する。
# ======================================================================
if ($SpeedTest) {
    Write-Host "`n--- Step 8: 実効スループット測定 (能動・データ通信あり) ---" -ForegroundColor Cyan
    Write-Host "    Cloudflare へ $SpeedTestConnections 本の並列コネクションで DL/UL を実測します（最大 ~$SpeedTestMaxMB MB / ~$SpeedTestUploadMB MB、数秒）..." -ForegroundColor DarkGray
    # ダウンロードで回線を埋めている最中に ping を打ち、無負荷時との差を見る。
    # 「速度は出るのに通話やゲームがカクつく」の正体はほぼこれ(バッファブロート)で、
    # 空いているときに何回 ping を打っても絶対に現れない。
    $loadTargets = @()
    if ($gw) { $loadTargets += $gw }
    if ($bestInternetQuality -and $bestInternetQuality.target) { $loadTargets += [string]$bestInternetQuality.target }
    elseif ($ExternalIps.Count -gt 0) { $loadTargets += $ExternalIps[0] }

    # 経路の中間ホップ(GWの先の1〜2個)も負荷時に測る。
    # 遅延が最初に膨らむ場所で「自宅ルータのキュー」か「ISP側」かを分離できる。
    # tracert は Step 5.7 で取得済みならそれを使う(なければここで取得)
    if (-not $script:firstHops) {
        try { $script:firstHops = @(Get-FirstHops -Target ($ExternalIps | Select-Object -First 1) -MaxHops 5) } catch { $script:firstHops = @() }
    }
    $script:hopIdleStats = @{}
    $script:hopNumberByIp = @{}
    $hopProbeIps = @($script:firstHops |
        Where-Object { $_.hop -ge 2 -and $_.ip -and $_.ip -ne $gw -and ($loadTargets -notcontains $_.ip) } |
        Select-Object -First 2)
    foreach ($h in $hopProbeIps) {
        # 無負荷時の基準値。応答しないホップ(ICMP無視)は負荷時測定からも外す
        $idle = Invoke-PingSeries -Target $h.ip -Count 5 -TimeoutMs $PingTimeoutMs
        if ($idle -and $null -ne $idle.avgMs) {
            $script:hopIdleStats[$h.ip] = $idle
            $script:hopNumberByIp[$h.ip] = $h.hop
            $loadTargets += $h.ip
        }
    }

    # GetNewClosure() は使わない。閉包は独自のモジュールスコープで動くため
    # スクリプト内で定義した関数(Invoke-PingSeries)を解決できなくなる。
    # 素のスクリプトブロックを & で呼べば、呼び出し元のスコープで動く。
    $script:LoadCpuSamples = @()
    $loadProbe = {
        $out = @{}
        # ping の合間に CPU/DPC も採る。「回線ではなく CPU の受信処理が律速」を
        # 判定できるのは、回線が実際に埋まっているこの瞬間だけ
        $cs = Get-CpuLoadSample; if ($cs) { $script:LoadCpuSamples += $cs }
        foreach ($t in $loadTargets) {
            if (-not $t) { continue }
            $out[$t] = Invoke-PingSeries -Target $t -Count 10 -TimeoutMs $PingTimeoutMs
            $cs = Get-CpuLoadSample; if ($cs) { $script:LoadCpuSamples += $cs }
        }
        return $out
    }

    $script:LoadProbeResult = $null
    # 測定中の TCP 再送率を出すため、DL/UL の前後で累積カウンタの差分を取る
    $tcpRetransBase = Get-TcpRetransSnapshot
    $dl = Measure-DownloadMbps -MaxSeconds $SpeedTestSeconds -MaxBytes ($SpeedTestMaxMB * 1MB) -Connections $SpeedTestConnections -WhileLoaded $loadProbe
    $ul = Measure-UploadMbps -TotalBytes ($SpeedTestUploadMB * 1MB) -Connections ([math]::Max(1, [int]($SpeedTestConnections / 2)))
    $tcpRetransAfter = Get-TcpRetransSnapshot
    $dlMbps   = if ($dl) { $dl.mbps } else { $null }
    $ulMbps   = if ($ul) { $ul.mbps } else { $null }

    # 比較の基準は「実際に通っている経路」の速度でなければ意味がない。
    # 有線NICが挿さっていても切断中なら、Wi-Fi のリンク速度と比べる。
    # なお Wi-Fi の表示速度は PHY レート（半二重・オーバーヘッド込み）なので、
    # 実効値はその 4〜6 割程度が正常。有線と同じしきい値では誤検知になる。
    if ($primaryAdapterKind -eq 'wifi' -and $script:primaryWifiPhyMbps) {
        $linkMbps   = [int]$script:primaryWifiPhyMbps
        $linkLabel  = 'Wi-Fi リンク'
        $lowRatio   = 0.25   # これを下回ると異常
        $highRatio  = 0.50   # これ以上なら無線としては上限に近い
        $isWifiPath = $true
    } else {
        $linkMbps   = $script:primaryLinkMbps
        $linkLabel  = 'NICリンク'
        $lowRatio   = 0.60
        $highRatio  = 0.85
        $isWifiPath = $false
    }

    if ($null -eq $dlMbps) {
        Add-Result -Step "実効スループット" -Layer "実測" -Status "skip" `
            -Detail "ダウンロード測定に失敗（外部到達不可/タイムアウト/プロキシ）" `
            -Hints @("インターネット到達性(Step 5)やプロキシ/セキュリティソフトを確認してください")
    } else {
        $detail = "下り $dlMbps Mbps"
        if ($null -ne $ulMbps) { $detail += " / 上り $ulMbps Mbps" }
        if ($linkMbps) { $detail += "（$linkLabel $linkMbps Mbps）" }
        $detail += " [$($dl.connections)本並列]"
        $tStatus = 'pass'; $tHints = @()

        # 上限バイト数で打ち切られた場合、測定区間が短く値がぶれやすい
        if ($dl.capped -and $dl.windowSec -lt 2.0) {
            $tHints += "転送量の上限($SpeedTestMaxMB MB)に $($dl.windowSec) 秒で到達したため、測定区間が短く値がぶれている可能性があります。10G 回線などでは -SpeedTestMaxMB を大きくして再測定してください"
        }

        if ($linkMbps -and $linkMbps -gt 0) {
            $pct = [int]([math]::Round($dlMbps * 100.0 / $linkMbps))
            $ratio = $dlMbps / $linkMbps
            if ($ratio -lt $lowRatio) {
                $tStatus = 'warn'
                $cfg = @()
                if ($script:autotuneState -and $script:autotuneState -ne 'normal') { $cfg += "TCP自動チューニング=$($script:autotuneState)" }
                if ($script:rssState -eq 'disabled') { $cfg += "RSS無効" }
                if ($script:ipv6BindEnabled -eq $false) { $cfg += "NICのIPv6無効" }
                $target = [int]($linkMbps * $highRatio)
                if ($cfg.Count -gt 0) {
                    $tHints += "$linkLabel $linkMbps Mbps に対し実測 $dlMbps Mbps（$pct%）と低速。$($cfg -join ' / ') が原因の可能性大 → 修正で ~$target Mbps が見込めます"
                    Add-Finding -Severity 'high' -Area '相関:速度↔設定' `
                        -Reason '実効速度がリンクを大きく下回り、速度低下の設定が見つかった' `
                        -Evidence "down=$dlMbps Mbps; link=$linkMbps Mbps ($pct%); $($cfg -join '; ')" `
                        -Action '管理者PowerShellで: netsh int tcp set global autotuninglevel=normal / rss=enabled（必要ならNICのIPv6有効化）'
                } elseif ($isWifiPath) {
                    $tHints += "Wi-Fi リンク $linkMbps Mbps に対し実測 $dlMbps Mbps（$pct%）。無線は PHY レートの 4〜6 割出れば正常なので、これは低すぎます。APとの距離・干渉・チャネル、または上流回線を確認してください"
                    Add-Finding -Severity 'medium' -Area '相関:速度' `
                        -Reason 'Wi-Fi のリンク速度に対して実効速度が低すぎる' `
                        -Evidence "down=$dlMbps Mbps; wifiLink=$linkMbps Mbps ($pct%)" `
                        -Action 'APに近づく/5GHz・6GHzへ切替/チャネル変更で再測定し、有線とも比較してください'
                } else {
                    $tHints += "$linkLabel $linkMbps Mbps に対し実測 $dlMbps Mbps（$pct%）と低速だが、PC設定は正常。回線混雑/上流/測定先/Wi-Fi/セキュリティソフトを確認してください"
                    Add-Finding -Severity 'medium' -Area '相関:速度' `
                        -Reason '実効速度がリンクを大きく下回る（PC設定は正常）' `
                        -Evidence "down=$dlMbps Mbps; link=$linkMbps Mbps ($pct%)" `
                        -Action '時間帯を変えて再測定、別の測定先、有線/別端末で比較してください'
                }
            } elseif ($ratio -ge $highRatio) {
                if ($isWifiPath) {
                    $tHints += "実測 $dlMbps Mbps は Wi-Fi リンク($linkMbps Mbps)に対し $pct% で、無線としては上限付近です。これ以上伸ばすには有線接続を検討してください"
                } elseif ($linkMbps -le 1000) {
                    $tHints += "実測がNICリンク($linkMbps Mbps)のほぼ上限（$pct%）。回線/ルータが上位対応なら PC の NIC がボトルネックです。2.5GbE/10GbE NIC で更に伸びる余地があります"
                    Add-Finding -Severity 'low' -Area 'ボトルネック' `
                        -Reason '実効速度がNICのリンク上限に達している（NICが律速）' `
                        -Evidence "down=$dlMbps Mbps ≒ link=$linkMbps Mbps ($pct%)" `
                        -Action '上位回線を活かすには 2.5GbE/10GbE NIC への更新を検討してください'
                } else {
                    $tHints += "実測 $dlMbps Mbps（$linkLabel の $pct%）。良好です"
                }
            } else {
                $tHints += "実測 $dlMbps Mbps（$linkLabel の $pct%）。おおむね良好です"
            }
        } else {
            $tHints += "リンク速度が不明のため比較なし（実測 下り $dlMbps Mbps）"
        }

        # ------------------------------------------------------------------
        # バッファブロート（負荷時の遅延増加）
        #   無負荷時の遅延と、回線を埋めた状態での遅延を比べる。
        #   増加が大きいほど、通話・ゲーム・会議が「速度は出ているのに」不安定になる。
        # ------------------------------------------------------------------
        $bloat = $null
        if ($script:LoadProbeResult) {
            $idleByTarget = @{}
            if ($gatewayQualityStats -and $gatewayQualityStats.target) { $idleByTarget[[string]$gatewayQualityStats.target] = $gatewayQualityStats }
            foreach ($iq in @($internetQualityStats)) { if ($iq.target) { $idleByTarget[[string]$iq.target] = $iq } }
            foreach ($hk in @($script:hopIdleStats.Keys)) { $idleByTarget[[string]$hk] = $script:hopIdleStats[$hk] }

            $worstIncrease = $null
            $bloatRows = @()
            foreach ($t in $script:LoadProbeResult.Keys) {
                $loaded = $script:LoadProbeResult[$t]
                $idle   = $idleByTarget[[string]$t]
                if (-not $loaded -or $null -eq $loaded.avgMs) { continue }
                $idleAvg = if ($idle -and $null -ne $idle.avgMs) { [double]$idle.avgMs } else { $null }
                $inc = if ($null -ne $idleAvg) { [math]::Round([double]$loaded.avgMs - $idleAvg, 1) } else { $null }
                $bloatRows += [PSCustomObject]@{
                    target       = [string]$t
                    idleAvgMs    = $idleAvg
                    loadedAvgMs  = $loaded.avgMs
                    loadedMaxMs  = $loaded.maxMs
                    loadedLossPct = $loaded.lossPct
                    increaseMs   = $inc
                }
                # 評価(grade)は GW と外部ターゲットのみで決める。中間ホップのルータは
                # 負荷時に ICMP 応答を後回しにする機種があり、実際の詰まりより
                # 大きく見えることがある(場所の特定には使えるが、量の評価には使えない)
                if ($null -ne $inc -and -not $script:hopIdleStats.ContainsKey([string]$t) -and
                    ($null -eq $worstIncrease -or $inc -gt $worstIncrease)) { $worstIncrease = $inc }
            }

            if ($null -ne $worstIncrease) {
                # 評価は DSLReports / Waveform と同じ考え方（無負荷比の増加量で切る）
                $grade = if ($worstIncrease -lt 5)   { 'A+' }
                         elseif ($worstIncrease -lt 30)  { 'A' }
                         elseif ($worstIncrease -lt 60)  { 'B' }
                         elseif ($worstIncrease -lt 200) { 'C' }
                         elseif ($worstIncrease -lt 400) { 'D' }
                         else { 'F' }
                $bloat = [PSCustomObject]@{
                    grade      = $grade
                    increaseMs = $worstIncrease
                    targets    = @($bloatRows)
                }

                $bStatus = 'pass'
                $bHints = @()
                if ($grade -in @('C', 'D', 'F')) {
                    $bStatus = 'warn'
                    $bHints += "通信が混んだときに遅延が $worstIncrease ms 増えます。速度自体は出ていても、通話・オンラインゲーム・ビデオ会議はこの瞬間に途切れたりカクついたりします"
                    $bHints += "原因はルーター（または回線終端装置）が送信待ちのデータを溜め込みすぎることです。ルーターに『帯域制御 / QoS / SQM / fq_codel』の設定があれば有効にし、上り帯域を実測値の 85〜90% に設定すると大きく改善します"
                    $bHints += "設定できないルーターの場合、機種変更が最も効果的です。回線速度を上げても改善しません"
                    Add-Finding -Severity $(if ($grade -eq 'F') { 'high' } else { 'medium' }) -Area 'バッファブロート' `
                        -Reason '回線が混んだときに遅延が大きく増える（速度ではなく遅延の問題）' `
                        -Evidence "評価=$grade; 遅延増加=+$worstIncrease ms" `
                        -Action 'ルーターの QoS/SQM を有効にし、上り帯域を実測の 85〜90% に設定してください'
                } elseif ($grade -eq 'B') {
                    $bHints += "負荷時の遅延増加は +$worstIncrease ms で、実用上は問題になりにくい範囲です"
                } elseif ($grade -eq 'A') {
                    $bHints += "負荷時の遅延増加は +$worstIncrease ms に収まっています。通話やゲームで問題になりにくい水準です"
                } else {
                    $bHints += "負荷をかけても遅延がほとんど増えません（+$worstIncrease ms）。非常に良好です"
                }

                # 遅延が増えているのが「宅内(ゲートウェイまで)」か「外部」かで対策が変わる。
                # 宅内側だけ増えるなら Wi-Fi や LAN の詰まりで、回線を変えても直らない。
                $gwRow   = @($bloatRows | Where-Object { $_.target -eq $gw })[0]
                $inetRow = @($bloatRows | Where-Object { $_.target -ne $gw -and -not $script:hopIdleStats.ContainsKey([string]$_.target) })[0]
                if ($gwRow -and $inetRow -and $null -ne $gwRow.increaseMs -and $null -ne $inetRow.increaseMs) {
                    if ($gwRow.increaseMs -ge 10 -and $gwRow.increaseMs -ge ($inetRow.increaseMs * 3)) {
                        $where = if ($primaryAdapterKind -eq 'wifi') { 'Wi-Fi 区間' } else { '宅内 LAN 区間' }
                        $bHints += "遅延が増えているのは主に${where}です（ゲートウェイまで +$($gwRow.increaseMs) ms に対し、外部までは +$($inetRow.increaseMs) ms）。回線側ではなく、$where の詰まりが原因です"
                        if ($primaryAdapterKind -eq 'wifi') {
                            $bHints += "有線接続に変えるか、AP に近づく・帯域幅の広いチャネルを使うことで改善します"
                        }
                    } elseif ($inetRow.increaseMs -ge 30) {
                        $bHints += "外部までの遅延も +$($inetRow.increaseMs) ms 増えています。ルーターの WAN 側または上流回線でデータが溜まっています"
                    }
                }

                # 中間ホップ(GWの先の1〜2個)の増加量から、詰まりの場所をさらに絞る。
                # GWは増えず、GW直後のホップから膨らむ → 自宅ルータのWAN側キュー/回線終端。
                # もっと先のホップから膨らむ → ISP網側(宅内の対策では直らない)
                if (@($script:hopIdleStats.Keys).Count -gt 0) {
                    $hopRows = @()
                    foreach ($hip in @($script:hopIdleStats.Keys)) {
                        $lrow = @($bloatRows | Where-Object { $_.target -eq $hip })[0]
                        if ($lrow -and $null -ne $lrow.increaseMs) {
                            $hopRows += [PSCustomObject]@{
                                hop = [int]$script:hopNumberByIp[$hip]; ip = $hip; increaseMs = $lrow.increaseMs
                            }
                        }
                    }
                    $hopRows = @($hopRows | Sort-Object hop)
                    if ($hopRows.Count -gt 0) {
                        $hopTxt = (@($hopRows | ForEach-Object { "hop$($_.hop)($($_.ip)) +$($_.increaseMs)ms" }) -join ' / ')
                        $gwInc = if ($gwRow -and $null -ne $gwRow.increaseMs) { [double]$gwRow.increaseMs } else { $null }
                        $firstFat = @($hopRows | Where-Object { $_.increaseMs -ge 30 })[0]
                        if ($worstIncrease -ge 60 -and $firstFat -and ($null -eq $gwInc -or $gwInc -lt 10)) {
                            if ($firstFat.hop -le 2) {
                                $bHints += "遅延が膨らみ始めるのはゲートウェイの直後(hop$($firstFat.hop))です。自宅ルータのWAN側送信キューか回線終端装置に溜まっており、ルータの QoS/SQM 設定で改善できる可能性が高い場所です（各ホップ: $hopTxt）"
                            } else {
                                $bHints += "ゲートウェイと直後のホップは増えておらず、hop$($firstFat.hop) から遅延が膨らんでいます。詰まりは ISP 網側にあり、宅内の設定変更では改善しません（各ホップ: $hopTxt）"
                            }
                        } else {
                            $bHints += "参考: 負荷時の中間ホップの遅延増加は $hopTxt（ルータは負荷時に ICMP 応答を後回しにすることがあるため、量ではなく場所の目安です）"
                        }
                    }
                }

                $bDetail = "評価 $grade（負荷時の遅延増加 +$worstIncrease ms）"
                Add-Result -Step "バッファブロート（負荷時の遅延）" -Layer "実測/品質" -Status $bStatus `
                    -Detail $bDetail `
                    -Evidence (@($bloatRows | ForEach-Object {
                        "$($_.target): 無負荷 $($_.idleAvgMs) ms → 負荷時 $($_.loadedAvgMs) ms (最大 $($_.loadedMaxMs) ms)"
                    }) -join ' | ') `
                    -Hints $bHints `
                    -Metrics $bloat
            }
        }

        Add-Result -Step "実効スループット" -Layer "実測/品質" -Status $tStatus `
            -Detail $detail `
            -Evidence "$($dl.connections) 本の並列コネクションで実測（$($dl.totalMB) MB / 測定区間 $($dl.windowSec) 秒、測定先 $($dl.url)）。参考値のため混雑や測定先で変動します" `
            -Hints $tHints `
            -Metrics ([PSCustomObject]@{
                downloadMbps    = $dlMbps
                uploadMbps      = $ulMbps
                linkMbps        = $linkMbps
                connections     = $dl.connections
                downloadedMB    = $dl.totalMB
                measureWindowSec = $dl.windowSec
                method          = $dl.method
            })

        # ------------------------------------------------------------------
        # 速度測定中の CPU / DPC 負荷
        #   実測が伸びない原因が「回線」ではなく「CPUの受信処理」のこともある。
        #   回線が埋まっている最中に採ったサンプルで律速かどうかを切り分ける。
        # ------------------------------------------------------------------
        if (@($script:LoadCpuSamples).Count -gt 0) {
            $cpuAvg = [math]::Round((@($script:LoadCpuSamples) | Measure-Object -Property cpuPct -Average).Average, 1)
            $cpuMax = [math]::Round((@($script:LoadCpuSamples) | Measure-Object -Property cpuPct -Maximum).Maximum, 1)
            $dpcAvg = [math]::Round((@($script:LoadCpuSamples | ForEach-Object { $_.dpcPct + $_.interruptPct }) | Measure-Object -Average).Average, 1)
            $cStatus = 'pass'; $cHints = @()
            $slowVsLink = ($linkMbps -and $dlMbps -and ($dlMbps / $linkMbps) -lt $lowRatio)
            if ($cpuAvg -ge 85) {
                $cStatus = 'warn'
                $cHints += "速度測定中の CPU 使用率が平均 $cpuAvg%（最大 $cpuMax%）に達しています。回線ではなく CPU が速度の上限を決めている可能性があります"
                Add-Finding -Severity $(if ($slowVsLink) { 'high' } else { 'medium' }) -Area 'CPU律速' `
                    -Reason '速度測定中に CPU 使用率がほぼ上限に達している' `
                    -Evidence "cpu avg=$cpuAvg% max=$cpuMax%; DPC+割り込み=$dpcAvg%" `
                    -Action '重い処理を止めて再測定してください。それでも高いなら RSS キュー数・NICドライバ・省電力設定を確認してください'
            } elseif ($dpcAvg -ge 25) {
                $cStatus = 'warn'
                $cHints += "CPU 全体には余裕がありますが、DPC/割り込み処理が平均 $dpcAvg% と高めです。NIC の受信割り込みが特定コアに集中して律速になっている可能性があります"
                Add-Finding -Severity 'medium' -Area 'CPU律速' `
                    -Reason '速度測定中の DPC/割り込み時間が高い（NIC割り込みの1コア集中）' `
                    -Evidence "DPC+割り込み avg=$dpcAvg%; cpu avg=$cpuAvg%" `
                    -Action 'NICドライバの更新と、Get-NetAdapterRss でRSSキューが複数コアに分散しているかを確認してください'
            } else {
                $cHints += "速度測定中も CPU 平均 $cpuAvg% / DPC+割り込み $dpcAvg% で、CPU は律速ではありません"
            }
            Add-Result -Step "速度測定中のCPU負荷" -Layer "実測/PC" -Status $cStatus `
                -Detail "CPU 平均 $cpuAvg% / 最大 $cpuMax% / DPC+割り込み $dpcAvg%" `
                -Evidence "ダウンロードで回線が埋まっている最中に $(@($script:LoadCpuSamples).Count) 回サンプリング" `
                -Hints $cHints `
                -Metrics ([PSCustomObject]@{ cpuAvgPct = $cpuAvg; cpuMaxPct = $cpuMax; dpcInterruptAvgPct = $dpcAvg; sampleCount = @($script:LoadCpuSamples).Count })
        }

        # ------------------------------------------------------------------
        # 速度測定中の TCP 再送率（送信方向）
        #   OS の累積カウンタの前後差分。高い = PC が送ったセグメントが経路で
        #   失われて送り直している = 上り経路(LAN/ルータ/回線)のパケット損失。
        #   下り方向の損失は相手サーバ側の再送になるため、この値には現れない
        # ------------------------------------------------------------------
        if ($tcpRetransBase -and $tcpRetransAfter) {
            $dSent    = $tcpRetransAfter.sent - $tcpRetransBase.sent
            $dRetrans = $tcpRetransAfter.retrans - $tcpRetransBase.retrans
            # 差分が小さすぎると率がぶれる。カウンタ巻き戻り(負)も捨てる
            if ($dSent -ge 2000 -and $dRetrans -ge 0) {
                $retransPct = [math]::Round(($dRetrans / $dSent) * 100, 2)
                $rtStatus = 'pass'; $rtHints = @()
                $rtSlowVsLink = ($linkMbps -and $dlMbps -and ($dlMbps / $linkMbps) -lt $lowRatio)
                if ($retransPct -ge 2) {
                    $rtStatus = 'warn'
                    $rtHints += "測定中の送信 TCP セグメントの $retransPct% が再送されています。上り経路のどこか(LANケーブル/Wi-Fi/ルータ/回線)でパケットが失われており、速度低下・アップロード不安定の直接原因になります"
                    Add-Finding -Severity $(if ($rtSlowVsLink) { 'high' } else { 'medium' }) -Area 'TCP再送' `
                        -Reason '速度測定中のTCP再送率が高い（上り経路のパケット損失）' `
                        -Evidence "retrans=$([long]$dRetrans)/$([long]$dSent) segments ($retransPct%)" `
                        -Action '有線なら LAN ケーブル・ポートを交換して再測定。Wi-Fi なら有線で比較。変わらなければルータ/回線側の損失です'
                } elseif ($retransPct -ge 0.5) {
                    $rtHints += "再送率 $retransPct% は軽度の損失です。実害は出にくい水準ですが、増加傾向なら物理層を確認してください"
                } else {
                    $rtHints += "再送率 $retransPct% で、上り経路のパケット損失はほぼありません"
                }
                Add-Result -Step "速度測定中のTCP再送" -Layer "実測/L4" -Status $rtStatus `
                    -Detail "再送率 $retransPct%（$([long]$dRetrans) / $([long]$dSent) セグメント）" `
                    -Evidence "OS の TCP 累積カウンタ(v4+v6)の測定前後差分。送信方向のみで、下り損失は含まれません" `
                    -Hints $rtHints `
                    -Metrics ([PSCustomObject]@{ retransPct = $retransPct; segmentsSent = [long]$dSent; segmentsRetransmitted = [long]$dRetrans })
            }
        }
    }
}

# ======================================================================
# Step 8.3: 宅内(LAN)スループット測定（-LanSpeedPath 指定時のみ）
#   インターネット速度測定だけでは「宅内が遅い」と「回線が遅い」を区別できない。
#   NAS 等の共有フォルダとの実転送で LAN 区間だけの速度を測り、切り分ける。
#   ※ Step 8.5(Δ測定)より前に置き、この転送負荷も破棄判定の対象に含める
# ======================================================================
if ($LanSpeedPath) {
    Write-Host "`n--- Step 8.3: 宅内(LAN)スループット測定 ---" -ForegroundColor Cyan
    Write-Host "    $LanSpeedPath へ一時ファイル ~$LanSpeedMB MB を書き込み/読み取りします..." -ForegroundColor DarkGray
    $lan = Measure-LanThroughput -Path $LanSpeedPath -SizeMB $LanSpeedMB
    if (-not $lan) {
        Add-Result -Step "宅内(LAN)スループット" -Layer "実測/LAN" -Status "skip" `
            -Detail "測定に失敗（パス到達不可・書き込み権限なし・空き容量不足）" `
            -Hints @("$LanSpeedPath にエクスプローラーでアクセスでき、書き込みできるか確認してください")
    } else {
        $lanStatus = 'pass'; $lanHints = @()
        $lanLink = $script:primaryLinkMbps
        $wanMbps = if ($SpeedTest -and (Test-Path variable:dlMbps)) { $dlMbps } else { $null }
        $detail = "読み取り $($lan.readMbps) Mbps / 書き込み $($lan.writeMbps) Mbps"
        if ($lanLink) { $detail += "（NICリンク $lanLink Mbps）" }

        if ($lan.readMethod -eq 'buffered') {
            $lanHints += "キャッシュ迂回の読み取りに失敗したため通常読み取りで測定しました。読み取り値は実際より速く出ている可能性があります"
        }
        if ($lanLink -and $lan.readMbps) {
            $ratio = $lan.readMbps / $lanLink
            if ($ratio -lt 0.6 -and ($null -eq $lan.writeMbps -or ($lan.writeMbps / $lanLink) -lt 0.6)) {
                $lanStatus = 'warn'
                $lanHints += "LAN 内の実測がリンク速度の6割未満です。経路上のスイッチ/ハブ、LANケーブル、対向機器のNIC、または対向機器のディスク(HDDなら ~1〜2Gbps が上限)がボトルネックです"
                Add-Finding -Severity 'medium' -Area '宅内LAN' `
                    -Reason 'LAN内の実効速度がリンク速度を大きく下回る' `
                    -Evidence "read=$($lan.readMbps) / write=$($lan.writeMbps) Mbps; link=$lanLink Mbps; 対向=$LanSpeedPath" `
                    -Action '経路上のスイッチの対応速度、ケーブルのカテゴリ、対向機器のNIC/ディスク性能を確認してください'
            } else {
                $lanHints += "LAN 区間はリンク速度に対して十分な速度が出ています"
            }
        }
        if ($wanMbps -and $lan.readMbps -and $wanMbps -lt ($lan.readMbps * 0.5)) {
            $lanHints += "宅内は $($lan.readMbps) Mbps 出ているのにインターネットは $wanMbps Mbps です。遅さの原因は宅内ではなく、ルータのWAN側・回線・ISP にあります"
            Add-Finding -Severity 'medium' -Area '相関:宅内vs回線' `
                -Reason '宅内LANは速いがインターネットだけ遅い → ボトルネックは回線側' `
                -Evidence "LAN read=$($lan.readMbps) Mbps >> WAN down=$wanMbps Mbps" `
                -Action 'ルータのWAN側リンク速度、接続方式、混雑時間帯、ISP を確認してください'
        }
        Add-Result -Step "宅内(LAN)スループット" -Layer "実測/LAN" -Status $lanStatus `
            -Detail $detail `
            -Evidence "対向: $LanSpeedPath（一時ファイル $($lan.sizeMB) MB、読み取りは$(if ($lan.readMethod -eq 'unbuffered') { 'キャッシュ迂回' } else { '通常(キャッシュ影響あり)' })。対向機器のディスク性能も含む値です）" `
            -Hints $lanHints `
            -Metrics ([PSCustomObject]@{ readMbps = $lan.readMbps; writeMbps = $lan.writeMbps; sizeMB = $lan.sizeMB; target = $LanSpeedPath; readMethod = $lan.readMethod; wanDownloadMbps = $wanMbps })
    }
}

# ======================================================================
# Step 8.5: NIC統計の増加量（診断中のΔ）
#   Step 1.5 の値は OS 起動時からの累積で、過去の一時的な問題か現在も
#   続いている問題かを区別できない。診断開始時のスナップショットと比較し、
#   この診断の間（-SpeedTest 時は高負荷区間を含む）に増えた分だけで判定する。
# ======================================================================
if ($script:nicStatBaseline -and $script:nicStatBaseline.Count -gt 0) {
    Write-Host "`n--- Step 8.5: L1/L2 (NIC統計の増加量) ---" -ForegroundColor Cyan
    $deltaElapsedSec = [math]::Round(((Get-Date) - $script:nicStatBaselineTime).TotalSeconds, 1)
    $deltaRows = @()
    $deltaStatus = 'pass'
    $deltaHints = @()
    $deltaDetails = @()
    $deltaWorstDisc = 0
    foreach ($name in @($script:nicStatBaseline.Keys)) {
        $st = $null
        try { $st = Get-NetAdapterStatistics -Name $name -ErrorAction Stop } catch { }
        if (-not $st) { continue }
        $base = $script:nicStatBaseline[$name]
        $dDelivered = ([double]($st.ReceivedUnicastPackets + $st.ReceivedMulticastPackets + $st.ReceivedBroadcastPackets)) - $base.rxDelivered
        $dRxDisc = [double]$st.ReceivedDiscardedPackets - $base.rxDisc
        $dRxErr  = [double]$st.ReceivedPacketErrors     - $base.rxErr
        $dTxDisc = [double]$st.OutboundDiscardedPackets - $base.txDisc
        $dTxErr  = [double]$st.OutboundPacketErrors     - $base.txErr
        # スリープ復帰やドライバ再初期化でカウンタが巻き戻った場合は評価しない
        if ($dDelivered -lt 0 -or $dRxDisc -lt 0 -or $dRxErr -lt 0) { continue }
        $dTotalRx  = $dDelivered + $dRxDisc
        $dDiscPpm  = if ($dTotalRx -gt 0) { [math]::Round(($dRxDisc / $dTotalRx) * 1e6, 1) } else { 0 }
        $deltaRows += [PSCustomObject]@{
            name       = $name
            seconds    = $deltaElapsedSec
            rxPackets  = [long]$dDelivered
            rxDiscards = [long]$dRxDisc
            rxErrors   = [long]$dRxErr
            txDiscards = [long]$dTxDisc
            txErrors   = [long]$dTxErr
            discardPpm = $dDiscPpm
        }
        $deltaDetails += "${name}: +破棄$([long]$dRxDisc) +エラー$([long]($dRxErr + $dTxErr)) / 受信$([long]$dDelivered)pkt"
        if ($dRxDisc -gt $deltaWorstDisc) { $deltaWorstDisc = $dRxDisc }

        # エラーの増加は物理層(ケーブル/コネクタ/ポート)の現在進行中の問題
        if (($dRxErr + $dTxErr) -gt 0) {
            $deltaStatus = 'warn'
            $deltaHints += "$name で診断中にパケットエラーが $([long]($dRxErr + $dTxErr)) 件増えました。ケーブル・コネクタ・NIC・対向ポートの物理的な問題が現在も起きています"
            Add-Finding -Severity 'medium' -Area 'L1/L2物理' `
                -Reason '診断中にNICのパケットエラーが増加(現在進行中)' `
                -Evidence "${name}: +rxErr=$([long]$dRxErr), +txErr=$([long]$dTxErr) / $deltaElapsedSec 秒" `
                -Action 'LANケーブルの交換・挿し直し、別ポートでの再測定を行ってください'
        }
        # 破棄の増加。エラー0で破棄だけ増える場合は物理層ではなく、
        # 受信バッファ不足・ドライバ・フィルタドライバ(セキュリティソフト)が候補
        if ($dRxDisc -ge 20 -and $dDiscPpm -ge 1000) {
            $deltaStatus = 'warn'
            $loadNote = if ($SpeedTest) { '高負荷測定中を含む区間で' } else { '通常負荷の区間で' }
            $deltaHints += "$name で $loadNote 受信破棄が $([long]$dRxDisc) 件($dDiscPpm ppm)増えました。累積値だけでなく現在も破棄が発生しています"
            if ($SpeedTest) {
                $deltaHints += "高負荷時のみ増える場合は NIC の受信バッファ不足が典型です。デバイスマネージャー→NICの詳細設定→『受信バッファ(Receive Buffers)』を最大値へ、またはドライバ更新を試してください"
            } else {
                $deltaHints += "負荷が軽いのに増え続ける場合は、NICドライバやセキュリティソフトのフィルタドライバを優先して調査してください"
            }
            Add-Finding -Severity 'medium' -Area 'L1/L2物理' `
                -Reason '診断中にNICの受信破棄が増加(現在進行中)' `
                -Evidence "${name}: +rxDisc=$([long]$dRxDisc) ($dDiscPpm ppm) / $deltaElapsedSec 秒$(if ($SpeedTest) { '(速度測定の高負荷を含む)' })" `
                -Action '受信バッファの増量、NICドライバ更新、セキュリティソフトの一時停止で切り分けてください'
        } elseif ($dRxDisc -gt 0) {
            $deltaHints += "$name で受信破棄が $([long]$dRxDisc) 件増えましたが、率($dDiscPpm ppm)としては軽微です。増え続けるか気になる場合は再実行して比較してください"
        }
    }
    if ($deltaRows.Count -gt 0) {
        if ($deltaStatus -eq 'pass' -and $deltaWorstDisc -eq 0) {
            $deltaHints += "診断中($deltaElapsedSec 秒)は破棄・エラーとも増えていません。Step 1.5 の累積値は過去に発生したもので、現在進行中の問題ではありません"
            if (-not $SpeedTest) {
                $deltaHints += "今回は軽負荷での確認です。高負荷時の破棄も調べるには -SpeedTest 付きで再実行してください"
            }
        }
        Add-Result -Step "NIC統計の増加量" -Layer "L1/L2" -Status $deltaStatus `
            -Detail ($deltaDetails -join ' | ') `
            -Evidence "診断開始時と終了時の差分($deltaElapsedSec 秒間)。累積値と違い『現在も起きているか』を示します$(if ($SpeedTest) { '。速度測定の高負荷区間を含みます' })" `
            -Hints $deltaHints `
            -Metrics ([PSCustomObject]@{ windowSeconds = $deltaElapsedSec; underLoad = [bool]$SpeedTest; adapters = @($deltaRows) })
    }
}

# ======================================================================
# Step 8.7: 配線品質の推定（有線のみ）
#   ケーブルは自分の規格を機器へ申告しないため「CAT6です」とは断定できない。
#   代わりに、リンク速度・両端の対応速度・エラーの増減・負荷中の実測を
#   組み合わせて「配線が今どの性能帯で動いていて、不良の兆候があるか」を
#   利用者向けの1つの答えにまとめる。
#   根拠: 1Gbps は4ペア全部が必要で 100Mbps は2ペアで動くため、
#   「1ペア断線 → 100M に落ちる」がケーブル不良の最も典型的な現れ方。
# ======================================================================
if ($primaryAdapterKind -ne 'wifi' -and $primaryWired) {
    Write-Host "`n--- Step 8.7: L1 (配線品質の推定) ---" -ForegroundColor Cyan
    $pw = $primaryWired
    $cw = @($nicStatRows | Where-Object { $_.name -eq $pw.name })[0]
    $dw = if (Test-Path variable:deltaRows) { @($deltaRows | Where-Object { $_.name -eq $pw.name })[0] } else { $null }

    $suspicion = 0          # 不良の疑いの強さ（3以上で「可能性が高い」）
    $cableSignals = @()
    $qHints = @()
    $neg = if ($pw.linkMbps) { [double]$pw.linkMbps } else { $null }
    $max = if ($pw.maxSupportedMbps) { [double]$pw.maxSupportedMbps } else { $null }

    # (1) GbE以上対応なのに100Mbpsリンク → ペア断線/接触不良の典型
    if ($neg -and $neg -le 100 -and $max -and $max -ge 1000) {
        $suspicion += 3
        $cableSignals += "NICは$([int]$max)Mbps対応なのに$([int]$neg)Mbpsでリンクしています。1Gbps以上はケーブル内の4ペア全部が必要で、100Mbpsは2ペアで動くため、1ペアの断線・接触不良でちょうどこの形になります"
    }
    # (2) 対応最大より大きく低い速度でのリンク
    elseif ($neg -and $max -and $max -ge ($neg * 2) -and $neg -ge 1000) {
        $suspicion += 1
        $cableSignals += "対応$([int]$max)Mbpsに対しリンクは$([int]$neg)Mbpsです（ケーブルのカテゴリ不足・劣化、または対向ポートの上限）"
    }
    # (3) パケットエラーの累積（FCS/CRC系＝信号品質の痕跡）
    if ($cw -and (([long]$cw.rxErrors + [long]$cw.txErrors) -ge 20)) {
        $suspicion += 1
        $cableSignals += "パケットエラーが累積 $([long]$cw.rxErrors + [long]$cw.txErrors) 件あります（起動後の合計。信号品質の問題の痕跡）"
    }
    # (4) 診断中にもエラーが増えた ＝ 現在進行中
    if ($dw -and (([long]$dw.rxErrors + [long]$dw.txErrors) -gt 0)) {
        $suspicion += 2
        $cableSignals += "診断中にもエラーが $([long]$dw.rxErrors + [long]$dw.txErrors) 件増えました（問題が現在も起きています）"
    }
    # (5) 速度測定中の上り再送率が高い
    if ((Test-Path variable:retransPct) -and $null -ne $retransPct -and $retransPct -ge 2) {
        $suspicion += 1
        $cableSignals += "速度測定中のTCP再送率が $retransPct% でした（上り経路のどこかでパケット損失）"
    }
    # (6) 宅内実測がリンク速度に対して大きく低い（-LanSpeedPath 測定時）
    if ((Test-Path variable:lan) -and $lan -and $lan.readMbps -and $neg -and (($lan.readMbps / $neg) -lt 0.4)) {
        $suspicion += 1
        $cableSignals += "宅内転送の実測($($lan.readMbps)Mbps)がリンク速度($([int]$neg)Mbps)を大きく下回っています（経路上のケーブル/スイッチ/対向機器のいずれか）"
    }

    if ($suspicion -eq 0) {
        $tier =
            if ($neg -ge 10000)    { "$([int]($neg/1000))Gbpsで安定動作 — CAT6A級の性能帯が出ています" }
            elseif ($neg -ge 2500) { "$(if ($neg -ge 1000) { "$($neg/1000)Gbps" } else { "$([int]$neg)Mbps" })で安定動作 — CAT5e級以上の性能帯が出ています" }
            elseif ($neg -ge 1000) { "1Gbpsで安定・エラーなし — 現在の使い方では配線に問題の兆候はありません" }
            elseif ($null -ne $neg) { "リンク$([int]$neg)Mbps・エラーなし" }
            else                   { "リンク速度は取得できませんでしたが、エラー等の不良の兆候はありません" }
        $qHints += "エラー増加・速度低下・リンク断のいずれの兆候も見つかりませんでした"
        if ($neg -eq 1000 -and $max -eq 1000) {
            $qHints += "両端とも1Gbps機器のため、このケーブルが2.5G/10Gに耐えるかは判定できません（上位速度の機器に替えたとき初めて差が出ます）"
        }
        $qHints += "※ LANケーブルは自分の規格(CAT5e/6/6A)を機器へ通知しないため、規格の断定ではなく『実際に出ている性能帯』で判定しています"
        Add-Result -Step "配線品質の推定" -Layer "L1/物理" -Status "pass" `
            -Detail $tier `
            -Evidence "リンク$(if ($null -ne $neg) { [int]$neg } else { '?' })Mbps / NIC対応$(if ($max) { [int]$max } else { '?' })Mbps / 累積エラー$(if ($cw) { [long]$cw.rxErrors + [long]$cw.txErrors } else { '?' })件" `
            -Hints $qHints `
            -Metrics ([PSCustomObject]@{ suspicionScore = 0; signals = @(); linkMbps = $neg; maxSupportedMbps = $max })
    } else {
        $qStatus = 'warn'
        $verdict = if ($suspicion -ge 3) { "LANケーブル/コネクタ不良の可能性が高い" }
                   else { "配線に注意サインあり（ケーブルとは断定できない段階）" }
        $qHints += $cableSignals
        $qHints += "切り分け手順: ①両端のコネクタを差し直す → ②別のLANケーブル(CAT6A表記の新品が確実)に交換 → ③ルータ/スイッチの別ポートへ → ④それでも同じならNICドライバ更新と対向機器を確認。1手ごとに再診断すると原因の段が特定できます"
        if ($suspicion -ge 3) {
            Add-Finding -Severity 'high' -Area '配線/ケーブル' `
                -Reason 'ケーブル/コネクタ不良を示す複数のシグナルが揃っている' `
                -Evidence ($cableSignals -join ' / ') `
                -Action 'LANケーブルを交換して再診断してください（両端の差し直し→ケーブル交換→別ポートの順）'
        }
        Add-Result -Step "配線品質の推定" -Layer "L1/物理" -Status $qStatus `
            -Detail $verdict `
            -Evidence "疑いスコア=$suspicion; リンク$(if ($neg) { [int]$neg } else { '?' })Mbps / NIC対応$(if ($max) { [int]$max } else { '?' })Mbps" `
            -Hints $qHints `
            -Metrics ([PSCustomObject]@{ suspicionScore = $suspicion; signals = @($cableSignals); linkMbps = $neg; maxSupportedMbps = $max })
    }
}

# ======================================================================
# 根本原因の相関分析（複数シグナルを組み合わせた上位の推定）
# ======================================================================
function Get-StepResult { param([string]$Name) return ($script:results | Where-Object { $_.step -eq $Name } | Select-Object -First 1) }

$rNic   = Get-StepResult 'NICエラー統計'
$rWifi  = Get-StepResult 'Wi-Fi 無線品質'
$rGwQ   = Get-StepResult 'ゲートウェイ連続 ping'
$rInetQ = Get-StepResult 'インターネット遅延・損失'
$rDns   = Get-StepResult 'DNS 名前解決'
$rHttps = Get-StepResult 'HTTPS 接続 (443)'

# 相関1: NICエラー高 + 主経路がWi-Fi → 無線の物理層が原因の可能性
if ($rNic -and $rNic.status -eq 'warn' -and $primaryAdapterKind -eq 'wifi') {
    Add-Finding -Severity 'high' -Area '相関:無線物理層' `
        -Reason 'Wi-Fi接続でNICエラーが多い → 電波品質が根本原因の可能性が高い' `
        -Evidence "primary=Wi-Fi; NICエラー統計=warn; Wi-Fi品質=$($rWifi.status)" `
        -Action 'まず5GHz/6GHzへ切替・AP近接・干渉源排除。改善しなければ有線で再測定して切り分けてください'
}

# 相関2: GWまでは良好だが外部品質が悪い → 上流(WAN/ISP/経路)が原因
if ($rGwQ -and $rGwQ.status -eq 'pass' -and $rInetQ -and $rInetQ.status -ne 'pass' -and $rInetQ.status -ne 'skip') {
    Add-Finding -Severity 'high' -Area '相関:上流回線' `
        -Reason 'LAN内(ゲートウェイまで)は安定だが外部通信のみ不安定 → ルータWAN側/ONU/ISP/経路混雑が濃厚' `
        -Evidence "gwQuality=pass; internetQuality=$($rInetQ.status)" `
        -Action 'ONU/ルータの再起動、ISP障害情報、混雑時間帯の再測定、有線での比較を行ってください'
}

# 相関3: ping(遅延/損失)は良好だが DNS と HTTPS が両方遅い → 回線速度ではなく名前解決/初期接続が体感速度のボトルネック
$gwQok   = (-not $rGwQ)   -or ($rGwQ.status   -in 'pass','skip')
$inetQok = (-not $rInetQ) -or ($rInetQ.status -in 'pass','skip')
if ($gwQok -and $inetQok -and $rDns -and $rDns.status -eq 'warn' -and $rHttps -and $rHttps.status -eq 'warn') {
    Add-Finding -Severity 'medium' -Area '相関:名前解決/初期接続' `
        -Reason 'pingは速いがDNSとHTTPS確立が遅い → 回線帯域ではなくDNS/初期接続が体感遅延の主因' `
        -Evidence "ping=良好; DNS=warn; HTTPS=warn" `
        -Action 'DNSを1.1.1.1/8.8.8.8へ変更、セキュリティソフトのSSL検査/Web保護を一時停止して比較してください'
}

# ======================================================================
# 結果まとめ
# ======================================================================
$pass  = @($results | Where-Object { $_.status -eq 'pass' }).Count
$fail  = @($results | Where-Object { $_.status -eq 'fail' }).Count
$warn  = @($results | Where-Object { $_.status -eq 'warn' }).Count
$skip  = @($results | Where-Object { $_.status -eq 'skip' }).Count

# 最初に失敗したステップを特定
$stoppedAt = $null
foreach ($r in $results) {
    if ($r.status -eq 'fail') { $stoppedAt = "$($r.layer) - $($r.step)"; break }
}

$overall = if ($fail -gt 0) { 'fail' } elseif ($warn -gt 0) { 'warn' } else { 'pass' }

if (@($findings).Count -eq 0 -and $overall -eq 'pass') {
    $normalEvidence = if ($NoExternalServices) {
        'NIC/Wi-Fi/ゲートウェイまでの各チェックがしきい値内（外部確認は未実施）'
    } else {
        'Wi-Fi/DNS/HTTPS/遅延/損失の各チェックがしきい値内'
    }
    Add-Finding -Severity 'low' -Area '再現なし' `
        -Reason '今回の短時間診断では明確な異常を検出していない' `
        -Evidence $normalEvidence `
        -Action '症状が出る時間帯に再実行し、結果を比較してください'
}

$summary = [PSCustomObject]@{
    timestamp     = (Get-Date).ToString("o")
    overallStatus = $overall
    pass          = $pass
    fail          = $fail
    warn          = $warn
    skip          = $skip
    total         = $results.Count
    stoppedAt     = $stoppedAt
    primaryAdapter = if ($primaryAdapter) {
        [PSCustomObject]@{
            name        = $primaryAdapter.Name
            kind        = $primaryAdapterKind
            description = $primaryAdapter.InterfaceDescription
            ipv4        = $primaryIp
            gateway     = $gw
            gatewayMac  = $script:gatewayMac
        }
    } else { $null }
    likelyCauses  = @($findings)
}

$output = [PSCustomObject]@{
    summary = $summary
    results = $results
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$output | ConvertTo-Json -Depth 10 | Set-Content $OutputPath -Encoding UTF8

# ======================================================================
# 履歴トレンド用のスナップショット
#   毎回の診断値を数十バイトに圧縮して history に残し、
#   「先週より DNS が遅い」「電波が徐々に落ちている」を後から比較できるようにする。
#   network-health.json 自体は毎回上書きされるため、ここで別途保存する。
# ======================================================================
try {
    $histDir = Join-Path $outDir "history"
    if (-not (Test-Path $histDir)) { New-Item -ItemType Directory -Path $histDir -Force | Out-Null }

    $gwQ    = Get-StepResult 'ゲートウェイ連続 ping'
    $inetQ  = Get-StepResult 'インターネット遅延・損失'
    $dnsR   = Get-StepResult 'DNS 名前解決'
    $httpsR = Get-StepResult 'HTTPS 接続 (443)'
    $wifiR  = Get-StepResult 'Wi-Fi 無線品質'
    $tputR  = Get-StepResult '実効スループット'
    $bloatR = Get-StepResult 'バッファブロート（負荷時の遅延）'

    # インターネット品質は複数ターゲットを測るので、代表(bestTarget)の値を取り出す
    $inetBest = $null
    if ($inetQ -and $inetQ.metrics -and $inetQ.metrics.targets) {
        $inetBest = @($inetQ.metrics.targets | Where-Object { $_.target -eq $inetQ.metrics.bestTarget })[0]
        if (-not $inetBest) { $inetBest = @($inetQ.metrics.targets)[0] }
    }

    # 接続先ネットワークの識別。自宅と出先では遅延も電波も別物なので、
    # 推移グラフで混ぜないようスナップショットに記録しておく。
    # ルータの MAC を第一候補にする（SSID は使い回され、IP は重複しやすい）。
    # SSID を名前に使うのは、実際に測った経路が無線のときだけ
    # （有線と Wi-Fi の同時接続時に、有線経路へ SSID の名前を付けないため）
    $pathSsid = if ($primaryAdapterKind -eq 'wifi' -and $wifiInfo -and $wifiInfo.ssid) { [string]$wifiInfo.ssid } else { $null }
    $netKey = if ($script:gatewayMac) { "gw$($script:gatewayMac)" }
              elseif ($pathSsid) { "ssid" + (($pathSsid -replace '[^a-zA-Z0-9]', '')) + $pathSsid.Length }
              elseif ($gw) { "ip" + ($gw -replace '[^0-9]', '') }
              else { 'unknown' }
    $netLabel = if ($pathSsid) { $pathSsid }
                elseif ($primaryAdapter -and $gw) { "$($primaryAdapter.Name) ($gw)" }
                elseif ($gw) { "有線 ($gw)" }
                else { '不明なネットワーク' }

    $snapshot = [PSCustomObject]@{
        timestamp     = $summary.timestamp
        networkId     = $netKey
        networkLabel  = $netLabel
        overallStatus = $overall
        adapterKind   = $primaryAdapterKind
        gwAvgMs       = if ($gwQ   -and $gwQ.metrics)   { $gwQ.metrics.avgMs }   else { $null }
        gwLossPct     = if ($gwQ   -and $gwQ.metrics)   { $gwQ.metrics.lossPct } else { $null }
        gwJitterMs    = if ($gwQ   -and $gwQ.metrics)   { $gwQ.metrics.jitterMs } else { $null }
        inetAvgMs     = if ($inetBest) { $inetBest.avgMs }   else { $null }
        inetLossPct   = if ($inetBest) { $inetBest.lossPct } else { $null }
        dnsAvgMs      = if ($dnsR   -and $dnsR.metrics)   { $dnsR.metrics.avgMs }   else { $null }
        httpsAvgMs    = if ($httpsR -and $httpsR.metrics) { $httpsR.metrics.avgMs } else { $null }
        wifiSignalPct = if ($wifiR  -and $wifiR.metrics)  { $wifiR.metrics.signalPercent } else { $null }
        wifiBand      = if ($wifiR  -and $wifiR.metrics)  { $wifiR.metrics.band } else { $null }
        downloadMbps  = if ($tputR  -and $tputR.metrics)  { $tputR.metrics.downloadMbps } else { $null }
        uploadMbps    = if ($tputR  -and $tputR.metrics)  { $tputR.metrics.uploadMbps } else { $null }
        bloatMs       = if ($bloatR -and $bloatR.metrics) { $bloatR.metrics.increaseMs } else { $null }
        bloatGrade    = if ($bloatR -and $bloatR.metrics) { $bloatR.metrics.grade } else { $null }
        nicDiscDeltaPpm = $(
            $deltaR = Get-StepResult 'NIC統計の増加量'
            if ($deltaR -and $deltaR.metrics -and $deltaR.metrics.adapters) {
                $w = (@($deltaR.metrics.adapters) | Measure-Object -Property discardPpm -Maximum).Maximum
                if ($null -ne $w) { [double]$w } else { $null }
            } else { $null }
        )
        lanReadMbps   = $(
            $lanR = Get-StepResult '宅内(LAN)スループット'
            if ($lanR -and $lanR.metrics) { $lanR.metrics.readMbps } else { $null }
        )
        retransPct    = $(
            $rtR = Get-StepResult '速度測定中のTCP再送'
            if ($rtR -and $rtR.metrics) { $rtR.metrics.retransPct } else { $null }
        )
    }
    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $snapshot | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $histDir "health-$stamp.json") -Encoding UTF8

    # 直近 120 件のみ保持（1日3回でも40日分。1ファイル数百バイト）
    $allHealth = @(Get-ChildItem -Path $histDir -Filter "health-*.json" -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if ($allHealth.Count -gt 120) {
        $allHealth | Select-Object -Skip 120 | Remove-Item -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "[!] 診断履歴の保存に失敗: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "===============================================" -ForegroundColor Magenta
$ovColor = switch ($overall) { 'pass' {'Green'} 'warn' {'Yellow'} default {'Red'} }
Write-Host (" 総合判定: {0}" -f $overall.ToUpper()) -ForegroundColor $ovColor
Write-Host ("   Pass: {0}  Fail: {1}  Warn: {2}  Skip: {3}" -f $pass, $fail, $warn, $skip) -ForegroundColor Gray
if ($stoppedAt) {
    Write-Host (" 最初の失敗: {0}" -f $stoppedAt) -ForegroundColor Red
}
if (@($findings).Count -gt 0) {
    Write-Host " 推定原因候補:" -ForegroundColor Cyan
    foreach ($f in $findings | Select-Object -First 5) {
        Write-Host ("   - [{0}] {1}: {2}" -f $f.severity, $f.area, $f.reason) -ForegroundColor Gray
    }
}
Write-Host "===============================================" -ForegroundColor Magenta
Write-Host "[+] 保存: $OutputPath" -ForegroundColor Green
