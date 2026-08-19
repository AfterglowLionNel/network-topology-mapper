<#
.SYNOPSIS
    直近の結果を確認し、通知に値する変化があればトースト通知を出す。

.DESCRIPTION
    定期実行（Register-ScheduledScan.ps1）は黙って結果を溜めるだけなので、
    こちらから見に行かないと変化に気づけない。このスクリプトは結果を読み、
    「見に行く価値がある」ときだけ通知する。

    通知するのは次の場合だけ:
      - 見覚えのない端末（過去に一度も記録がない未登録の機器）が現れた
      - 診断が fail になった（つながらない）
      - 診断値が過去と比べて明確に悪化した（外れ値ではなく傾向として）

    毎回鳴らすと無視されるようになるため、同じ内容の通知は既定 12 時間抑制する。

.PARAMETER OutputDir
    結果の置き場所（既定: ..\output）

.PARAMETER QuietHours
    同じ内容の通知を抑制する時間（既定 12）

.PARAMETER Force
    抑制を無視して必ず通知する（動作確認用）

.PARAMETER WhatIfOnly
    通知せず、何を通知するかだけを表示する
#>

[CmdletBinding()]
param(
    [string]$OutputDir = "$PSScriptRoot\..\output",
    [int]$QuietHours = 12,
    [switch]$Force,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = "Continue"

function ConvertTo-Base64Text {
    param([AllowEmptyString()][string]$Value)
    return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value))
}

function Show-Toast {
    <#
        Windows のトースト通知を出す。

        PowerShell 7 には WinRT の型投影がないため、固定ヘルパースクリプトを
        Windows PowerShell 5.1 で実行する。タイトル等はコードへ埋め込まず、
        UTF-8 Base64 の引数として渡す。
    #>
    param([string]$Title, [string]$Message, [string]$LaunchPath)

    $ps51 = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $helper = Join-Path $PSScriptRoot 'Show-NetworkToast.ps1'
    if ((Test-Path -LiteralPath $ps51) -and (Test-Path -LiteralPath $helper)) {
        try {
            $arguments = @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-WindowStyle', 'Hidden', '-File', $helper,
                '-TitleBase64', (ConvertTo-Base64Text $Title),
                '-MessageBase64', (ConvertTo-Base64Text $Message),
                '-LaunchPathBase64', (ConvertTo-Base64Text $LaunchPath)
            )
            & $ps51 @arguments 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch { }
    }

    Write-Host "[!] トースト通知を出せませんでした（内容はここに表示します）" -ForegroundColor Yellow
    Write-Host "    $Title / $Message" -ForegroundColor Gray
    return $false
}

function Get-Median2 {
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $s = @($Values | Sort-Object)
    $n = $s.Count
    if ($n % 2 -eq 1) { return [double]$s[[int](($n - 1) / 2)] }
    return ([double]$s[[int]($n / 2) - 1] + [double]$s[[int]($n / 2)]) / 2
}

$reportPath = Join-Path $OutputDir "diagram.html"
$historyDir = Join-Path $OutputDir "history"
$stateFile  = Join-Path $OutputDir "alert-state.json"

$alerts = @()

# ------------------------------------------------------------------
# 1. 診断が fail（つながらない）
# ------------------------------------------------------------------
$healthPath = Join-Path $OutputDir "network-health.json"
if (Test-Path $healthPath) {
    try {
        $health = Get-Content $healthPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($health.summary -and $health.summary.overallStatus -eq 'fail') {
            $stopped = if ($health.summary.stoppedAt) { $health.summary.stoppedAt } else { '不明な段階' }
            $alerts += @{
                key     = "fail:$stopped"
                title   = 'ネットワークに問題があります'
                message = "$stopped で失敗しました。レポートを開いて原因候補を確認してください。"
            }
        }
    } catch { }
}

# ------------------------------------------------------------------
# 2. 見覚えのない端末
#    New-NetworkDiagram.ps1 と同じ考え方: 同じネットワークの過去スナップショット
#    すべてに一度も出ていない端末で、かつ known-devices に登録がないもの。
# ------------------------------------------------------------------
$knownMacs = @{}
$knownIps  = @{}
$knownPath = Join-Path $PSScriptRoot "..\config\known-devices.json"
if (Test-Path $knownPath) {
    try {
        $kd = Get-Content $knownPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $entries = if ($kd.devices) { $kd.devices } else { $kd }
        foreach ($prop in $entries.PSObject.Properties) {
            if ($prop.Name -like '_*') { continue }
            $nm = ($prop.Name -replace '[^0-9A-Fa-f]', '').ToUpper()
            if ($prop.Name -match '^\d{1,3}(\.\d{1,3}){3}$') { $knownIps[$prop.Name] = $true }
            elseif ($nm.Length -eq 12) { $knownMacs[$nm] = $true }
        }
    } catch { }
}

if (Test-Path $historyDir) {
    # 最新のスナップショットと、それ以前のすべてを比べる（ネットワークごと）
    $snapFiles = @(Get-ChildItem -Path $historyDir -Filter "devices-*.json" -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($snapFiles.Count -ge 2) {
        $latestFile = $snapFiles[-1]
        # 同じネットワークのものだけを対象にする
        $netPrefix = $null
        if ($latestFile.Name -match '^(devices-[^-]+)-\d{8}-\d{6}\.json$') { $netPrefix = $Matches[1] }
        $sameNet = if ($netPrefix) { @($snapFiles | Where-Object { $_.Name -like "$netPrefix-*" }) } else { @($snapFiles) }

        if ($sameNet.Count -ge 2) {
            try {
                $latest = Get-Content $sameNet[-1].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $seenMacs = @{}
                $seenIps  = @{}
                foreach ($f in ($sameNet | Select-Object -SkipLast 1)) {
                    $sj = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                    foreach ($d in @($sj.devices)) {
                        if ($d.mac) { $seenMacs[(($d.mac -replace '[^0-9A-Fa-f]', '').ToUpper())] = $true }
                        if ($d.ip)  { $seenIps[[string]$d.ip] = $true }
                    }
                    foreach ($ip in @($sj.deviceIps)) { if ($ip) { $seenIps[[string]$ip] = $true } }
                }

                $newOnes = @()
                foreach ($d in @($latest.devices)) {
                    $mac = if ($d.mac) { ($d.mac -replace '[^0-9A-Fa-f]', '').ToUpper() } else { $null }
                    if ($mac -and $knownMacs.ContainsKey($mac)) { continue }
                    if ($d.ip -and $knownIps.ContainsKey([string]$d.ip)) { continue }
                    $isNew = if ($mac) { -not $seenMacs.ContainsKey($mac) } else { -not $seenIps.ContainsKey([string]$d.ip) }
                    if ($isNew) { $newOnes += $d }
                }

                if ($newOnes.Count -gt 0) {
                    $names = @($newOnes | ForEach-Object {
                        if ($_.name) { "$($_.name) ($($_.ip))" } else { [string]$_.ip }
                    }) -join ', '
                    $alerts += @{
                        key     = "newdev:" + (@($newOnes | ForEach-Object { [string]$_.mac; [string]$_.ip }) -join '|')
                        title   = "見覚えのない端末が $($newOnes.Count) 台つながっています"
                        message = "$names。心当たりがなければ Wi-Fi パスワードの変更を検討してください。"
                    }
                }
            } catch { }
        }
    }
}

# ------------------------------------------------------------------
# 3. 診断値の明確な悪化
#    直近 3 回の中央値と、それ以前の中央値を比べる（1 回の外れ値では鳴らさない）
# ------------------------------------------------------------------
if (Test-Path $historyDir) {
    $healthFiles = @(Get-ChildItem -Path $historyDir -Filter "health-*.json" -ErrorAction SilentlyContinue | Sort-Object Name)
    if ($healthFiles.Count -ge 6) {
        try {
            $snaps = @()
            foreach ($f in ($healthFiles | Select-Object -Last 40)) {
                $snaps += (Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json)
            }
            # 現在のネットワークのものだけ
            $curNet = $snaps[-1].networkId
            if ($curNet) { $snaps = @($snaps | Where-Object { $_.networkId -eq $curNet }) }

            $watch = @(
                @{ key = 'inetAvgMs';    label = 'インターネットの応答'; unit = 'ms';   worseIsUp = $true }
                @{ key = 'dnsAvgMs';     label = 'DNS の応答';           unit = 'ms';   worseIsUp = $true }
                @{ key = 'downloadMbps'; label = '実効速度';             unit = 'Mbps'; worseIsUp = $false }
                @{ key = 'bloatMs';      label = '負荷時の遅延増加';     unit = 'ms';   worseIsUp = $true }
            )
            foreach ($w in $watch) {
                $vals = @($snaps | ForEach-Object { $_.($w.key) } | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { [double]$_ })
                if ($vals.Count -lt 6) { continue }
                $recent = Get-Median2 -Values @($vals | Select-Object -Last 3)
                $base   = Get-Median2 -Values @($vals | Select-Object -First ($vals.Count - 3))
                if ($null -eq $base -or $base -eq 0) { continue }
                $ratio = ($recent - $base) / [math]::Abs($base)
                # 通知は「気づいて行動する価値がある」水準に絞る（推移グラフより厳しめ）
                $worse = if ($w.worseIsUp) { $ratio -gt 0.5 } else { $ratio -lt -0.4 }
                if ($worse) {
                    $alerts += @{
                        key     = "degrade:$($w.key)"
                        title   = "$($w.label)が悪化しています"
                        message = ("以前の中央値 {0:N1} {2} → 直近 {1:N1} {2}。レポートの推移グラフで確認してください。" -f $base, $recent, $w.unit)
                    }
                }
            }
        } catch { }
    }
}

# ------------------------------------------------------------------
# 通知（同じ内容の連発を抑制）
# ------------------------------------------------------------------
if ($alerts.Count -eq 0) {
    Write-Host "[+] 通知が必要な変化はありません" -ForegroundColor Green
    return
}

$state = @{}
if ((Test-Path $stateFile) -and -not $Force) {
    try {
        $sj = Get-Content $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $sj.PSObject.Properties) { $state[$p.Name] = $p.Value }
    } catch { }
}

$now = Get-Date
$sent = 0
foreach ($a in $alerts) {
    if (-not $Force -and $state.ContainsKey($a.key)) {
        try {
            $last = [datetime]$state[$a.key]
            if (($now - $last).TotalHours -lt $QuietHours) {
                Write-Host "[-] 抑制中（$([int](($now - $last).TotalHours)) 時間前に通知済み）: $($a.title)" -ForegroundColor DarkGray
                continue
            }
        } catch { }
    }

    if ($WhatIfOnly) {
        Write-Host "[通知予定] $($a.title): $($a.message)" -ForegroundColor Cyan
    } else {
        Write-Host "[!] 通知: $($a.title)" -ForegroundColor Yellow
        [void](Show-Toast -Title $a.title -Message $a.message -LaunchPath $reportPath)
    }
    $state[$a.key] = $now.ToString("o")
    $sent++
}

if (-not $WhatIfOnly -and $sent -gt 0) {
    try {
        ([PSCustomObject]$state) | ConvertTo-Json -Depth 3 | Set-Content $stateFile -Encoding UTF8
    } catch { }
}

Write-Host "[+] $sent 件を通知しました" -ForegroundColor Green
