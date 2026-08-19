<#
.SYNOPSIS
    ゲートウェイと外部ターゲットへ連続 ping を打ち、遅延スパイク・瞬断(パケットロス)を
    時系列で記録・検出する「モニタモード」。断続的な不調（たまに遅い/切れる）の捕捉に使う。

.DESCRIPTION
    指定時間だけ一定間隔で各ターゲットへ ping し、各サンプルの RTT/タイムアウトを記録。
    終了後にターゲット別のベースライン(中央値)を基準にスパイクと瞬断を検出し、
    JSON と HTML タイムライン(SVG)を出力する。

.PARAMETER DurationSec
    監視する秒数（デフォルト 60 秒）

.PARAMETER IntervalMs
    ping 間隔（ミリ秒、デフォルト 1000）

.PARAMETER Targets
    監視ターゲット。未指定ならゲートウェイ + 8.8.8.8 を自動採用

.PARAMETER OutputDir
    出力先（デフォルト .\output）

.EXAMPLE
    .\Watch-Network.ps1
    .\Watch-Network.ps1 -DurationSec 120 -IntervalMs 500
#>

[CmdletBinding()]
param(
    [int]$DurationSec = 60,
    [int]$IntervalMs = 1000,
    [string[]]$Targets,
    [string]$OutputDir = "$PSScriptRoot\..\output",
    [int]$TimeoutMs = 1500,
    [double]$SpikeFactor = 3.0,
    [int]$SpikeMinMs = 50,
    # 未指定ターゲットへ外部 IP を自動追加しない（既定ゲートウェイだけを監視）
    [switch]$NoExternalServices,
    # 統合レポート(diagram.html)側で表示する場合に、monitor.html を自動で開かせない
    [switch]$NoOpen
)

$ErrorActionPreference = "Continue"

function Get-DefaultGateway {
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                 Sort-Object RouteMetric | Select-Object -First 1
        if ($route) { return $route.NextHop }
    } catch { }
    return $null
}

# ターゲット決定
if (-not $Targets -or $Targets.Count -eq 0) {
    $Targets = @()
    $gw = Get-DefaultGateway
    if ($gw) { $Targets += $gw }
    if (-not $NoExternalServices) { $Targets += '8.8.8.8' }
}
$Targets = @($Targets | Where-Object { $_ } | Select-Object -Unique)

Write-Host "=========================================" -ForegroundColor Magenta
Write-Host " Network Topology Mapper - Monitor" -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta
Write-Host ("監視対象: {0}" -f ($Targets -join ', ')) -ForegroundColor Cyan
Write-Host ("監視時間: {0} 秒 / 間隔: {1} ms" -f $DurationSec, $IntervalMs) -ForegroundColor Cyan
Write-Host "中断するには Ctrl+C を押してください。" -ForegroundColor DarkGray
Write-Host ""

# ラベル（GW / INET）を付与して見やすく
$labelMap = @{}
for ($i = 0; $i -lt $Targets.Count; $i++) {
    $t = $Targets[$i]
    if ($i -eq 0 -and $t -notmatch '^\d+\.\d+\.\d+\.\d+$' ) { $labelMap[$t] = $t }
}
$gwDetected = Get-DefaultGateway
foreach ($t in $Targets) {
    if ($t -eq $gwDetected) { $labelMap[$t] = "GW($t)" }
    elseif (-not $labelMap.ContainsKey($t)) { $labelMap[$t] = $t }
}

# PC側NIC統計（破棄/エラー）の時系列。瞬断と同じ瞬間に破棄が増えるなら、
# 原因はルータや回線ではなく PC 側(NIC/ドライバ/受信バッファ)にある。
function Get-NicCounters {
    param([string]$Name)
    try {
        $st = Get-NetAdapterStatistics -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            disc = [double]$st.ReceivedDiscardedPackets + [double]$st.OutboundDiscardedPackets
            err  = [double]$st.ReceivedPacketErrors + [double]$st.OutboundPacketErrors
        }
    } catch { return $null }
}
$nicName = $null
try {
    $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } |
                Sort-Object RouteMetric | Select-Object -First 1
    if ($defRoute) {
        $ad = Get-NetAdapter -InterfaceIndex $defRoute.ifIndex -ErrorAction SilentlyContinue
        if ($ad) { $nicName = $ad.Name }
    }
} catch { }
$nicSamples = @()
$nicPrev = $null
$nicLastSampleAt = Get-Date
# リンク速度の変化(再ネゴシエーション)も追う。監視中に速度が変わるのは
# ケーブル/コネクタの接触不良や省電力による再リンクの典型
$linkFlaps = @()
$prevLinkSpeed = $null
if ($nicName) {
    $nicPrev = Get-NicCounters -Name $nicName
    try { $prevLinkSpeed = [string](Get-NetAdapter -Name $nicName -ErrorAction Stop).LinkSpeed } catch { }
}

# サンプル収集
$samples = @{}       # target -> array of @{ t=elapsedSec; rtt=ms or $null }
foreach ($t in $Targets) { $samples[$t] = @() }

$ping = New-Object System.Net.NetworkInformation.Ping
$startTime = Get-Date
$endTime = $startTime.AddSeconds($DurationSec)
$tick = 0

while ((Get-Date) -lt $endTime) {
    $tick++
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    $lineParts = @("[{0,5}s]" -f $elapsed)

    foreach ($t in $Targets) {
        $rtt = $null
        try {
            $reply = $ping.Send($t, $TimeoutMs)
            if ($reply.Status -eq 'Success') { $rtt = [double]$reply.RoundtripTime }
        } catch { }

        $samples[$t] += [PSCustomObject]@{ t = $elapsed; rtt = $rtt }

        if ($null -eq $rtt) {
            $lineParts += ("{0}=LOSS" -f $labelMap[$t])
        } else {
            $lineParts += ("{0}={1}ms" -f $labelMap[$t], [int]$rtt)
        }
    }

    # 簡易ライブ表示（ロスや高遅延を色付け）
    $hasLoss = $false; $hasHigh = $false
    foreach ($t in $Targets) {
        $last = $samples[$t][-1]
        if ($null -eq $last.rtt) { $hasLoss = $true }
        elseif ($last.rtt -ge 150) { $hasHigh = $true }
    }
    $color = if ($hasLoss) { 'Red' } elseif ($hasHigh) { 'Yellow' } else { 'Gray' }
    Write-Host ($lineParts -join '  ') -ForegroundColor $color

    # NIC統計は1秒以上あけてサンプリング（間隔の短い設定でも負荷を増やさない）。
    # リンク速度フラップ検出はカウンタ取得の成否と無関係に動かす
    # （起動時に Get-NicCounters が失敗しても、再ネゴシエーションは検出したい）
    if ($nicName -and ((Get-Date) - $nicLastSampleAt).TotalMilliseconds -ge 950) {
        if ($nicPrev) {
            $nicCur = Get-NicCounters -Name $nicName
            if ($nicCur) {
                $nicSamples += [PSCustomObject]@{
                    t    = $elapsed
                    disc = [long][math]::Max(0, $nicCur.disc - $nicPrev.disc)
                    err  = [long][math]::Max(0, $nicCur.err  - $nicPrev.err)
                    loss = $hasLoss
                }
                $nicPrev = $nicCur
            }
        }
        # リンク速度の変化を検出（1秒間隔のこのタイミングで一緒に見る）
        try {
            $curSpeed = [string](Get-NetAdapter -Name $nicName -ErrorAction Stop).LinkSpeed
            if ($prevLinkSpeed -and $curSpeed -and $curSpeed -ne $prevLinkSpeed) {
                $linkFlaps += [PSCustomObject]@{ t = $elapsed; from = $prevLinkSpeed; to = $curSpeed }
                Write-Host ("[{0,5}s] リンク速度が変化: {1} → {2}" -f $elapsed, $prevLinkSpeed, $curSpeed) -ForegroundColor Yellow
            }
            if ($curSpeed) { $prevLinkSpeed = $curSpeed }
        } catch { }
        $nicLastSampleAt = Get-Date
    }

    $sleepMs = $IntervalMs
    if ($sleepMs -gt 0) { Start-Sleep -Milliseconds $sleepMs }
}
$ping.Dispose()

# ターゲット別の集計・スパイク/瞬断検出
function Get-Median {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = @($Values | Sort-Object)
    $n = $sorted.Count
    if ($n % 2 -eq 1) { return $sorted[[int](($n - 1) / 2)] }
    return [math]::Round((($sorted[$n/2 - 1] + $sorted[$n/2]) / 2), 1)
}

$targetSummaries = @()
foreach ($t in $Targets) {
    $data = $samples[$t]
    $total = $data.Count
    $okRtts = @($data | Where-Object { $null -ne $_.rtt } | ForEach-Object { [double]$_.rtt })
    $lossCount = @($data | Where-Object { $null -eq $_.rtt }).Count
    $lossPct = if ($total -gt 0) { [math]::Round(($lossCount / $total) * 100, 1) } else { 0 }

    $median = Get-Median -Values $okRtts
    $avg = if ($okRtts.Count -gt 0) { [math]::Round((($okRtts | Measure-Object -Average).Average), 1) } else { $null }
    $max = if ($okRtts.Count -gt 0) { [math]::Round((($okRtts | Measure-Object -Maximum).Maximum), 1) } else { $null }
    $min = if ($okRtts.Count -gt 0) { [math]::Round((($okRtts | Measure-Object -Minimum).Minimum), 1) } else { $null }

    # スパイク閾値: max(median*factor, median+SpikeMinMs)
    $spikeThreshold = $null
    if ($null -ne $median) {
        $spikeThreshold = [math]::Max($median * $SpikeFactor, $median + $SpikeMinMs)
    }
    $spikes = @()
    if ($null -ne $spikeThreshold) {
        $spikes = @($data | Where-Object { $null -ne $_.rtt -and $_.rtt -ge $spikeThreshold })
    }

    # 連続ロス（瞬断）区間を抽出
    $outages = @()
    $runStart = $null; $runLen = 0
    foreach ($s in $data) {
        if ($null -eq $s.rtt) {
            if ($runLen -eq 0) { $runStart = $s.t }
            $runLen++
        } else {
            if ($runLen -ge 1) { $outages += [PSCustomObject]@{ startSec = $runStart; samples = $runLen } }
            $runLen = 0
        }
    }
    if ($runLen -ge 1) { $outages += [PSCustomObject]@{ startSec = $runStart; samples = $runLen } }

    $jitter = $null
    if ($okRtts.Count -ge 2) {
        $diffs = @()
        for ($i = 1; $i -lt $okRtts.Count; $i++) { $diffs += [math]::Abs($okRtts[$i] - $okRtts[$i-1]) }
        $jitter = [math]::Round((($diffs | Measure-Object -Average).Average), 1)
    }

    $verdict = 'good'
    if ($lossPct -ge 5 -or $outages.Count -ge 1) { $verdict = 'bad' }
    elseif ($spikes.Count -ge 1 -or ($null -ne $jitter -and $jitter -gt 30)) { $verdict = 'unstable' }

    $targetSummaries += [PSCustomObject]@{
        target         = $t
        label          = $labelMap[$t]
        totalSamples   = $total
        lossCount      = $lossCount
        lossPct        = $lossPct
        minMs          = $min
        avgMs          = $avg
        medianMs       = $median
        maxMs          = $max
        jitterMs       = $jitter
        spikeThreshold = if ($spikeThreshold) { [math]::Round($spikeThreshold,1) } else { $null }
        spikeCount     = $spikes.Count
        outageCount    = $outages.Count
        outages        = @($outages)
        verdict        = $verdict
    }
}

# NIC統計の集計と、瞬断との同時発生の判定
# （カウンタが取れなくてもリンクフラップだけ検出できた場合があるため OR 条件）
$nicSummary = $null
if ($nicName -and ($nicSamples.Count -gt 0 -or $linkFlaps.Count -gt 0)) {
    $totDisc   = [long](($nicSamples | Measure-Object -Property disc -Sum).Sum)
    $totErr    = [long](($nicSamples | Measure-Object -Property err  -Sum).Sum)
    $lossTicks = @($nicSamples | Where-Object { $_.loss })
    $coTicks   = @($nicSamples | Where-Object { $_.disc -gt 0 -and $_.loss })
    $nicHint =
        if ($linkFlaps.Count -gt 0) {
            $flapTxt = (@($linkFlaps | Select-Object -First 3 | ForEach-Object { "$($_.t)s: $($_.from)→$($_.to)" }) -join ' / ')
            "監視中にリンク速度が $($linkFlaps.Count) 回変わりました($flapTxt)。ケーブル/コネクタの接触不良、または省電力設定による再リンクの典型です。両端の差し直しとケーブル交換を試してください"
        } elseif ($totDisc -eq 0 -and $totErr -eq 0) {
            "監視中、PC側NIC($nicName)の破棄・エラーは増えていません。不調が出ていても PC の NIC が原因ではない可能性が高いです"
        } elseif ($lossTicks.Count -gt 0 -and $coTicks.Count -ge [math]::Ceiling($lossTicks.Count / 2.0)) {
            "瞬断と同じタイミングで NIC の破棄が増えています($($coTicks.Count)/$($lossTicks.Count)回)。ルータや回線ではなく、PC側(NIC/ドライバ/受信バッファ)が原因の疑いが濃いです"
        } elseif ($totErr -gt 0) {
            "NIC のエラーが監視中に $totErr 件増えました。ケーブル・コネクタなど物理層を確認してください"
        } else {
            "NIC の破棄が監視中に $totDisc 件増えましたが、瞬断とは一致していません。継続的に増えるならドライバや受信バッファを確認してください"
        }
    $nicSummary = [PSCustomObject]@{
        adapter         = $nicName
        totalDiscards   = $totDisc
        totalErrors     = $totErr
        lossTicks       = $lossTicks.Count
        coincidentTicks = $coTicks.Count
        linkFlaps       = @($linkFlaps)
        hint            = $nicHint
        samples         = @($nicSamples)
    }
}

# ==========================================
# Windows イベントログとの突き合わせ
#   監視ウィンドウ中の Wi-Fi 切断・NIC/リンク系・DHCP のイベントを取得し、
#   瞬断ティックと時刻で相関させる。ping は「いつ切れたか」しか語らないが、
#   イベントログには「なぜ」（切断理由コード・ドライバリセット等）が残っている
# ==========================================
$lossTimes = @()
foreach ($t in $Targets) {
    foreach ($s in @($samples[$t])) { if ($null -eq $s.rtt) { $lossTimes += [double]$s.t } }
}
$lossTimes = @($lossTimes | Sort-Object -Unique)

$netEvents = @()
$addEvent = {
    param($e, [string]$source)
    $msg = [string]$e.Message
    $firstLine = if ($msg) { (@($msg -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 1) } else { "(詳細なし)" }
    if ($firstLine.Length -gt 160) { $firstLine = $firstLine.Substring(0, 160) + '…' }
    $offset = [math]::Round(($e.TimeCreated - $startTime).TotalSeconds, 1)
    $near = $false
    foreach ($lt in $lossTimes) { if ([math]::Abs($lt - $offset) -le 5) { $near = $true; break } }
    $script:netEvents += [PSCustomObject]@{
        time      = $e.TimeCreated.ToString('HH:mm:ss')
        offsetSec = $offset
        source    = $source
        provider  = [string]$e.ProviderName
        id        = [int]$e.Id
        level     = [string]$e.LevelDisplayName
        message   = $firstLine
        nearLoss  = $near
    }
}
# 個々のイベントの Message 取得はリソースDLL欠落で失敗することがあるため、
# 1件の失敗で同じログの残り全件を捨てないよう、イベント単位でも握る
# (1) Wi-Fi の接続/切断（8003=切断。メッセージに切断理由が入る）
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WLAN-AutoConfig/Operational'; Id = @(8001, 8002, 8003); StartTime = $startTime } -ErrorAction Stop)) {
        try { & $addEvent $e 'Wi-Fi' } catch { }
    }
} catch { }
# (2) System ログの NIC/リンク/TCP まわりの警告・エラー
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = @(2, 3); StartTime = $startTime } -ErrorAction Stop)) {
        try {
            if ($e.ProviderName -match 'NDIS|Tcpip|Dhcp|WLAN|netw|e1[cdrx]|e2f|rt\d|Realtek|Intel|Broadcom|Mellanox|Killer' -or
                "$($e.Message)" -match 'リンク|切断|ネットワーク|link|disconnect') {
                & $addEvent $e 'System'
            }
        } catch { }
    }
} catch { }
# (3) DHCP クライアント（アドレス更新失敗など）
try {
    foreach ($e in @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Dhcp-Client/Admin'; Level = @(2, 3); StartTime = $startTime } -ErrorAction Stop)) {
        try { & $addEvent $e 'DHCP' } catch { }
    }
} catch { }
$netEvents = @($netEvents | Sort-Object offsetSec)
$eventSummary = $null
if ($netEvents.Count -gt 0) {
    $coincident = @($netEvents | Where-Object { $_.nearLoss })
    $evHint =
        if ($lossTimes.Count -gt 0 -and $coincident.Count -gt 0) {
            "瞬断の前後±5秒にイベントログの記録が $($coincident.Count) 件あります。切断の理由はログ側に残っている可能性が高いです（下の一覧を確認）"
        } elseif ($lossTimes.Count -gt 0) {
            "瞬断はありましたが、同時刻の Windows イベントは記録されていません。PC の外側(ルータ/回線/AP)で起きている可能性が高いです"
        } else {
            "監視中にネットワーク関連のイベントが $($netEvents.Count) 件記録されました（瞬断はなし）"
        }
    $eventSummary = [PSCustomObject]@{
        count           = $netEvents.Count
        coincidentCount = $coincident.Count
        hint            = $evHint
        events          = @($netEvents)
    }
}

# JSON 出力
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$monitorObj = [PSCustomObject]@{
    startedAt   = $startTime.ToString("o")
    durationSec = $DurationSec
    intervalMs  = $IntervalMs
    targets     = @($targetSummaries)
    nicStats    = $nicSummary
    winEvents   = $eventSummary
    samples     = $samples
}
$jsonPath = Join-Path $OutputDir "network-monitor.json"
$monitorObj | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

# ==========================================
# HTML タイムライン（SVG）生成
# ==========================================
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

$colors = @('#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6')
$chartW = 1100; $chartH = 160; $padL = 50; $padR = 20; $padT = 16; $padB = 24

$chartsHtml = ""
$ci = 0
foreach ($ts in $targetSummaries) {
    $t = $ts.target
    $data = $samples[$t]
    $color = $colors[$ci % $colors.Count]
    $ci++

    $okRtts = @($data | Where-Object { $null -ne $_.rtt } | ForEach-Object { [double]$_.rtt })
    $yMax = if ($okRtts.Count -gt 0) { [math]::Max(($okRtts | Measure-Object -Maximum).Maximum, 10) } else { 10 }
    $yMax = [math]::Ceiling($yMax / 10) * 10
    $n = [math]::Max($data.Count, 1)
    $plotW = $chartW - $padL - $padR
    $plotH = $chartH - $padT - $padB

    $points = @()
    $lossTicks = ""
    $spikeDots = ""
    for ($i = 0; $i -lt $data.Count; $i++) {
        $x = [math]::Round($padL + ($plotW * $i / [math]::Max($n - 1, 1)), 1)
        $s = $data[$i]
        if ($null -eq $s.rtt) {
            # 瞬断: 下部に赤いタテ線
            $lossTicks += "<line x1='$x' y1='$($padT)' x2='$x' y2='$($padT+$plotH)' stroke='#ef4444' stroke-width='1.5' opacity='0.5'/>"
        } else {
            $y = [math]::Round($padT + $plotH - ($plotH * [math]::Min($s.rtt, $yMax) / $yMax), 1)
            $points += "$x,$y"
            if ($null -ne $ts.spikeThreshold -and $s.rtt -ge $ts.spikeThreshold) {
                $spikeDots += "<circle cx='$x' cy='$y' r='3' fill='#f59e0b'/>"
            }
        }
    }
    $polyline = if ($points.Count -gt 0) { "<polyline points='$($points -join ' ')' fill='none' stroke='$color' stroke-width='1.6'/>" } else { "" }

    # ベースライン(中央値)の水平線
    $medLine = ""
    if ($null -ne $ts.medianMs) {
        $my = [math]::Round($padT + $plotH - ($plotH * [math]::Min($ts.medianMs, $yMax) / $yMax), 1)
        $medLine = "<line x1='$padL' y1='$my' x2='$($padL+$plotW)' y2='$my' stroke='#9ca3af' stroke-dasharray='4 4' stroke-width='1'/>"
    }

    $verdictBadge = switch ($ts.verdict) {
        'good'     { "<span style='background:#dcfce7;color:#166534;padding:2px 10px;border-radius:12px'>安定</span>" }
        'unstable' { "<span style='background:#fef3c7;color:#92400e;padding:2px 10px;border-radius:12px'>不安定（スパイク有）</span>" }
        'bad'      { "<span style='background:#fee2e2;color:#991b1b;padding:2px 10px;border-radius:12px'>問題あり（瞬断/高ロス）</span>" }
        default    { "" }
    }

    $enc = { param($x) [System.Web.HttpUtility]::HtmlEncode([string]$x) }
    $chartsHtml += @"
    <section>
        <h2>$(& $enc $ts.label) $verdictBadge</h2>
        <div style="font-size:13px;color:#4b5563;margin-bottom:8px">
            サンプル $($ts.totalSamples) / ロス $($ts.lossCount)件 ($($ts.lossPct)%) /
            min $($ts.minMs) ・ 中央値 $($ts.medianMs) ・ avg $($ts.avgMs) ・ max $($ts.maxMs) ms /
            ジッタ $($ts.jitterMs) ms / スパイク $($ts.spikeCount)件 / 瞬断 $($ts.outageCount)回
        </div>
        <svg viewBox="0 0 $chartW $chartH" style="width:100%;height:auto;background:#fafafa;border:1px solid #e5e7eb;border-radius:8px">
            <text x="6" y="$($padT+6)" font-size="11" fill="#6b7280">$yMax ms</text>
            <text x="6" y="$($padT+$plotH)" font-size="11" fill="#6b7280">0</text>
            $medLine
            $lossTicks
            $polyline
            $spikeDots
        </svg>
        <div style="font-size:12px;color:#9ca3af;margin-top:4px">
            折線=RTT / 破線=中央値(ベースライン) / 橙点=スパイク / 赤縦線=タイムアウト(瞬断)
        </div>
    </section>
"@
}

# PC側NIC統計のチャート（破棄/エラーの増加を時系列バーで表示）
$nicChartHtml = ""
if ($nicSummary) {
    $enc2 = { param($x) [System.Web.HttpUtility]::HtmlEncode([string]$x) }
    $nsam = @($nicSummary.samples)
    $yMaxN = 5
    foreach ($s in $nsam) { $m = $s.disc + $s.err; if ($m -gt $yMaxN) { $yMaxN = $m } }
    $plotW = $chartW - $padL - $padR
    $plotH = $chartH - $padT - $padB
    $bars = ""
    $barW = [math]::Max(1.5, [math]::Round($plotW / [math]::Max($nsam.Count, 1) * 0.6, 1))
    foreach ($s in $nsam) {
        $x = [math]::Round($padL + ($plotW * $s.t / [math]::Max($DurationSec, 1)), 1)
        if ($s.loss) {
            $bars += "<line x1='$x' y1='$padT' x2='$x' y2='$($padT+$plotH)' stroke='#ef4444' stroke-width='1.5' opacity='0.35'/>"
        }
        if ($s.disc -gt 0) {
            $h = [math]::Round($plotH * $s.disc / $yMaxN, 1)
            $bars += "<rect x='$($x - $barW/2)' y='$($padT + $plotH - $h)' width='$barW' height='$h' fill='#b45309' opacity='0.9'/>"
        }
        if ($s.err -gt 0) {
            $h = [math]::Round($plotH * $s.err / $yMaxN, 1)
            $bars += "<rect x='$($x - $barW/2)' y='$($padT + $plotH - $h)' width='$barW' height='$h' fill='#ef4444' opacity='0.9'/>"
        }
    }
    $nicChartHtml = @"
    <section>
        <h2>PC側 NIC 統計（$(& $enc2 $nicSummary.adapter)）</h2>
        <div style="font-size:13px;color:#4b5563;margin-bottom:8px">
            監視中の増加: 破棄 $($nicSummary.totalDiscards) 件 / エラー $($nicSummary.totalErrors) 件 /
            瞬断と同時 $($nicSummary.coincidentTicks) 回
        </div>
        <svg viewBox="0 0 $chartW $chartH" style="width:100%;height:auto;background:#fafafa;border:1px solid #e5e7eb;border-radius:8px">
            <text x="6" y="$($padT+6)" font-size="11" fill="#6b7280">$yMaxN 件</text>
            <text x="6" y="$($padT+$plotH)" font-size="11" fill="#6b7280">0</text>
            $bars
        </svg>
        <div style="font-size:12px;color:#9ca3af;margin-top:4px">
            茶バー=破棄の増加 / 赤バー=エラーの増加 / 赤縦線=その時刻に瞬断（1秒ごとの増加量）
        </div>
        <div style="font-size:13px;color:#374151;margin-top:8px">$(& $enc2 $nicSummary.hint)</div>
    </section>
"@
}

# Windows イベントの一覧（瞬断と重なったものを強調）
$eventsHtml = ""
if ($eventSummary) {
    $enc3 = { param($x) [System.Web.HttpUtility]::HtmlEncode([string]$x) }
    $evRows = ""
    foreach ($ev in @($eventSummary.events)) {
        $mark = if ($ev.nearLoss) { " style='background:#fef2f2'" } else { "" }
        $flag = if ($ev.nearLoss) { "●" } else { "" }
        $evRows += "<tr$mark><td>$(& $enc3 $ev.time)</td><td style='text-align:right'>$(& $enc3 $ev.offsetSec)s</td><td>$(& $enc3 $ev.source)</td><td style='text-align:right'>$($ev.id)</td><td>$(& $enc3 $ev.message)</td><td style='color:#b91c1c;text-align:center'>$flag</td></tr>"
    }
    $eventsHtml = @"
    <section>
        <h2>Windows イベントログ（監視ウィンドウ中）</h2>
        <div style="font-size:13px;color:#4b5563;margin-bottom:8px">
            記録 $($eventSummary.count) 件 / うち瞬断の前後±5秒 $($eventSummary.coincidentCount) 件（右端の●）
        </div>
        <div style="overflow-x:auto">
        <table style="width:100%;border-collapse:collapse;font-size:12px">
            <tr style="text-align:left;color:#6b7280;border-bottom:1px solid #e5e7eb">
                <th style="padding:4px 6px">時刻</th><th>経過</th><th>種別</th><th>ID</th><th>内容</th><th>瞬断と同時</th>
            </tr>
            $evRows
        </table>
        </div>
        <div style="font-size:13px;color:#374151;margin-top:8px">$(& $enc3 $eventSummary.hint)</div>
    </section>
"@
}

# 総合判定
$worst = 'good'
if (@($targetSummaries | Where-Object { $_.verdict -eq 'bad' }).Count -gt 0) { $worst = 'bad' }
elseif (@($targetSummaries | Where-Object { $_.verdict -eq 'unstable' }).Count -gt 0) { $worst = 'unstable' }

$overallText = switch ($worst) {
    'good'     { '監視中、明確なスパイク・瞬断は検出されませんでした' }
    'unstable' { '遅延スパイクを検出。断続的に遅くなる傾向があります' }
    'bad'      { '瞬断/高パケットロスを検出。接続が不安定です' }
}

# GW安定・外部不安定の切り分けヒント
$splitHint = ""
$gwSum = $targetSummaries | Where-Object { $_.target -eq $gwDetected } | Select-Object -First 1
$inetSum = $targetSummaries | Where-Object { $_.target -ne $gwDetected } | Select-Object -First 1
if ($gwSum -and $inetSum) {
    if ($gwSum.verdict -eq 'good' -and $inetSum.verdict -ne 'good') {
        $splitHint = "ゲートウェイ(LAN内)は安定で外部のみ不安定 → ルータWAN側/ONU/ISP/経路混雑が疑われます。"
    } elseif ($gwSum.verdict -ne 'good') {
        $splitHint = "ゲートウェイまでで既に不安定 → Wi-Fi電波/LANケーブル/ルータ本体/宅内配線が疑われます。有線で再測定して切り分けてください。"
    }
}

$startedText = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
$ovColor = switch ($worst) { 'good' {'#10b981'} 'unstable' {'#f59e0b'} default {'#ef4444'} }

$html = @"
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>ネットワーク モニタ</title>
<style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, 'Segoe UI', 'Hiragino Sans', 'Yu Gothic', sans-serif; margin:0; padding:24px; background:#f5f7fa; color:#1f2937; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { background: linear-gradient(135deg,#0f766e,#14b8a6); color:#fff; padding:24px 32px; border-radius:12px; margin-bottom:24px; }
    header h1 { margin:0 0 8px 0; font-size:22px; }
    header .meta { font-size:13px; opacity:.9; }
    section { background:#fff; padding:20px 24px; border-radius:12px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,.05); }
    section h2 { margin-top:0; font-size:17px; border-bottom:2px solid #e5e7eb; padding-bottom:8px; display:flex; align-items:center; gap:10px; }
    .overall { padding:16px 20px; border-radius:10px; font-weight:600; font-size:16px; border-left:6px solid $ovColor; background:#f9fafb; }
    .split-hint { margin-top:10px; font-size:13px; color:#374151; font-weight:400; }
    footer { text-align:center; color:#6b7280; font-size:12px; padding:16px 0; }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>📡 ネットワーク モニタリング結果</h1>
        <div class="meta">開始: $startedText ｜ 監視 $DurationSec 秒 ｜ 間隔 $IntervalMs ms ｜ 対象 $($Targets.Count) 件</div>
    </header>

    <section>
        <div class="overall">$overallText
            $(if ($splitHint) { "<div class='split-hint'>💡 $([System.Web.HttpUtility]::HtmlEncode($splitHint))</div>" })
        </div>
    </section>

    $chartsHtml
    $nicChartHtml
    $eventsHtml

    <footer>Generated by Network Topology Mapper (Monitor) at $startedText</footer>
</div>
</body>
</html>
"@

$htmlPath = Join-Path $OutputDir "monitor.html"
$html | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "===============================================" -ForegroundColor Magenta
$wColor = switch ($worst) { 'good' {'Green'} 'unstable' {'Yellow'} default {'Red'} }
Write-Host (" モニタ結果: {0}" -f $overallText) -ForegroundColor $wColor
foreach ($ts in $targetSummaries) {
    Write-Host ("   {0}: ロス {1}% / 中央値 {2}ms / max {3}ms / スパイク {4} / 瞬断 {5}" -f `
        $ts.label, $ts.lossPct, $ts.medianMs, $ts.maxMs, $ts.spikeCount, $ts.outageCount) -ForegroundColor Gray
}
if ($nicSummary) {
    Write-Host ("   NIC({0}): 破棄 +{1} / エラー +{2} / 瞬断と同時 {3}回" -f `
        $nicSummary.adapter, $nicSummary.totalDiscards, $nicSummary.totalErrors, $nicSummary.coincidentTicks) -ForegroundColor Gray
    Write-Host ("   ヒント: {0}" -f $nicSummary.hint) -ForegroundColor Cyan
}
if ($eventSummary) {
    Write-Host ("   イベントログ: {0} 件 (瞬断の前後±5秒 {1} 件)" -f $eventSummary.count, $eventSummary.coincidentCount) -ForegroundColor Gray
    foreach ($ev in @($eventSummary.events | Where-Object { $_.nearLoss } | Select-Object -First 3)) {
        Write-Host ("     [{0}] {1} #{2}: {3}" -f $ev.time, $ev.source, $ev.id, $ev.message) -ForegroundColor Yellow
    }
    Write-Host ("   ヒント: {0}" -f $eventSummary.hint) -ForegroundColor Cyan
}
if ($splitHint) { Write-Host ("   ヒント: {0}" -f $splitHint) -ForegroundColor Cyan }
Write-Host "===============================================" -ForegroundColor Magenta
Write-Host ("[+] JSON: {0}" -f $jsonPath) -ForegroundColor Green
Write-Host ("[+] HTML: {0}" -f $htmlPath) -ForegroundColor Green

if (-not $NoOpen) {
    try { Start-Process $htmlPath } catch { }
}
