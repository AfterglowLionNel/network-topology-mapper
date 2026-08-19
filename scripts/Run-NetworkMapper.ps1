<#
.SYNOPSIS
    安全な基本診断、承認付き LAN 調査、モニタをまとめて実行する。

.DESCRIPTION
    引数なしでは PC・NIC・既定ゲートウェイまでの基本診断だけを行う。
    LAN 内への能動プローブは -DetailedScan、外部サービスへの通信は
    -ExternalChecks または -SpeedTest を明示した場合だけ行う。

.EXAMPLE
    .\Run-NetworkMapper.ps1
    外部通信や LAN 全探索をしない基本診断。

.EXAMPLE
    .\Run-NetworkMapper.ps1 -DetailedScan
    対象 CIDR と最大ホスト数を表示し、確認後に LAN を調査する。

.EXAMPLE
    .\Run-NetworkMapper.ps1 -DiagnoseOnly -ExternalChecks
    基本診断にインターネット到達性・DNS・HTTPS の確認を加える。

.EXAMPLE
    .\Run-NetworkMapper.ps1 -DiagnoseOnly -SpeedTest
    最大約 200 MB の実効速度測定を行う。
#>

[CmdletBinding(DefaultParameterSetName = 'Basic')]
param(
    # 旧 -Full は Alias として互換維持するが、実行前の確認は省略しない。
    [Parameter(ParameterSetName = 'Detailed')]
    [Alias('Full')]
    [switch]$DetailedScan,

    [Parameter(ParameterSetName = 'Basic')]
    [switch]$DiagnoseOnly,

    [Parameter(ParameterSetName = 'Monitor')]
    [switch]$Monitor,

    [Parameter(ParameterSetName = 'Public')]
    [switch]$PublicReport,

    [Parameter(ParameterSetName = 'Monitor')]
    [ValidateRange(5, 86400)]
    [int]$MonitorDuration = 60,

    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$Light,

    # 非対話の自動化で、表示済みの LAN 能動調査を承認する。
    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$ApproveActiveScan,

    # 複数の安全な NIC がある場合に対象を絞る。
    [Parameter(ParameterSetName = 'Detailed')]
    [int[]]$ScanInterfaceIndex,

    [Parameter(ParameterSetName = 'Detailed')]
    [ValidateRange(1, 1022)]
    [int]$MaxScanHosts = 1022,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [Parameter(ParameterSetName = 'Monitor')]
    [switch]$ExternalChecks,

    # 外部サービス通信を強制的に無効化する単一のキルスイッチ。
    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [Parameter(ParameterSetName = 'Monitor')]
    [switch]$NoExternalServices,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$Notify,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$SpeedTest,

    # 旧呼び出しとの互換用。速度測定は現在、明示した場合だけ実行する。
    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$NoSpeedTest,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [ValidateRange(1, 16)]
    [int]$SpeedTestConnections = 6,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [ValidateRange(1, 2000)]
    [int]$SpeedTestMaxMB = 180,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [ValidateRange(1, 500)]
    [int]$SpeedTestUploadMB = 20,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [string]$LanSpeedPath,

    [Parameter(ParameterSetName = 'Basic')]
    [Parameter(ParameterSetName = 'Detailed')]
    [ValidateRange(1, 4096)]
    [int]$LanSpeedMB = 200,

    [Parameter(ParameterSetName = 'Detailed')]
    [switch]$SkipInternetInfo,

    [Parameter(ParameterSetName = 'Detailed')]
    [Parameter(ParameterSetName = 'Monitor')]
    [Parameter(ParameterSetName = 'Public')]
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'

function Test-PrivateIpv4Address {
    param([string]$IpAddress)
    try {
        $ip = [Net.IPAddress]::Parse($IpAddress)
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
        $b = $ip.GetAddressBytes()
        return ($b[0] -eq 10) -or
               ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
               ($b[0] -eq 192 -and $b[1] -eq 168)
    } catch {
        return $false
    }
}

function Get-Ipv4ScanRange {
    param(
        [string]$IpAddress,
        [int]$PrefixLength
    )
    if (-not (Test-PrivateIpv4Address $IpAddress) -or $PrefixLength -lt 22 -or $PrefixLength -gt 30) {
        return $null
    }
    $bytes = [Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    $networkBytes = [byte[]]::new(4)
    $bits = $PrefixLength
    for ($i = 0; $i -lt 4; $i++) {
        $mask = if ($bits -ge 8) { $bits -= 8; 255 }
                elseif ($bits -gt 0) { $m = 256 - [math]::Pow(2, (8 - $bits)); $bits = 0; $m }
                else { 0 }
        $networkBytes[$i] = [byte]($bytes[$i] -band [int]$mask)
    }
    $hostCount = [int]([math]::Pow(2, (32 - $PrefixLength)) - 2)
    return [PSCustomObject]@{
        ipAddress = $IpAddress
        prefix    = $PrefixLength
        network   = ($networkBytes -join '.')
        cidr      = "$(($networkBytes -join '.'))/$PrefixLength"
        hostCount = $hostCount
    }
}

function Test-DisallowedAdapterName {
    param([string]$Name, [string]$Description)
    $text = "$Name $Description"
    return $text -match '(?i)\b(VPN|WireGuard|Tailscale|ZeroTier|OpenVPN|Tunnel|TAP|Npcap|Loopback|Bluetooth|Container)\b|Virtual|VMware|VirtualBox|Hyper-V|vEthernet|WSL'
}

function Get-SafeScanTargets {
    param([int[]]$RequestedInterfaceIndex)

    $profiles = @{}
    foreach ($profile in @(Get-NetConnectionProfile -ErrorAction SilentlyContinue)) {
        $profiles[[int]$profile.InterfaceIndex] = [string]$profile.NetworkCategory
    }

    $targets = @()
    foreach ($adapter in @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })) {
        $index = [int]$adapter.ifIndex
        if ($RequestedInterfaceIndex -and $RequestedInterfaceIndex -notcontains $index) { continue }
        $hardwareProperty = $adapter.PSObject.Properties['HardwareInterface']
        if ($hardwareProperty -and -not [bool]$hardwareProperty.Value) { continue }
        if (Test-DisallowedAdapterName -Name ([string]$adapter.Name) -Description ([string]$adapter.InterfaceDescription)) { continue }
        if ($profiles[$index] -ne 'Private') { continue }

        foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {
            if ($ip.SkipAsSource -eq $true) { continue }
            $range = Get-Ipv4ScanRange -IpAddress ([string]$ip.IPAddress) -PrefixLength ([int]$ip.PrefixLength)
            if (-not $range) { continue }
            $targets += [PSCustomObject]@{
                interfaceIndex = $index
                adapterName    = [string]$adapter.Name
                address        = $range.ipAddress
                cidr           = $range.cidr
                hostCount      = $range.hostCount
                profile        = $profiles[$index]
            }
        }
    }
    return @($targets | Sort-Object interfaceIndex, cidr -Unique)
}

function Confirm-ActiveScan {
    param(
        [array]$Targets,
        [bool]$AllowExternal,
        [bool]$IncludeSpeedTest,
        [int]$DownloadMB,
        [int]$UploadMB,
        [switch]$Approved
    )

    $totalHosts = [int](($Targets | Measure-Object -Property hostCount -Sum).Sum)
    Write-Host ''
    Write-Host 'これから行う能動調査' -ForegroundColor Yellow
    foreach ($target in $Targets) {
        Write-Host "  - $($target.adapterName) (ifIndex $($target.interfaceIndex)): $($target.cidr) / 最大 $($target.hostCount) 台" -ForegroundColor White
    }
    Write-Host "  合計の最大対象数: $totalHosts 台" -ForegroundColor White
    Write-Host '  LAN 内: ping、SSDP/mDNS、NetBIOS、HTTP、代表ポート確認' -ForegroundColor DarkGray
    if ($AllowExternal) {
        Write-Host '  外部: Cloudflare/Google/GitHub等への到達確認、公開IP・OUI情報の取得' -ForegroundColor DarkGray
    } else {
        Write-Host '  外部サービスへの通信: なし' -ForegroundColor Green
    }
    if ($IncludeSpeedTest) {
        Write-Host "  速度測定: Cloudflare へ最大 約 $($DownloadMB + $UploadMB) MB（下り $DownloadMB / 上り $UploadMB MB）" -ForegroundColor Yellow
    }

    if ($Approved) { return $true }
    $inputRedirected = $true
    try { $inputRedirected = [Console]::IsInputRedirected } catch { }
    if ($inputRedirected) {
        throw '非対話実行では -ApproveActiveScan が必要です。表示された CIDR が自分の管理するネットワークであることを確認してください。'
    }
    $answer = (Read-Host 'この範囲を調査しますか？ [y/N]').Trim().ToUpperInvariant()
    return $answer -in @('Y', 'YES')
}

$diagnoseScript = Join-Path $PSScriptRoot 'Test-NetworkHealth.ps1'
$collectScript  = Join-Path $PSScriptRoot 'Collect-NetworkInfo.ps1'
$identifyScript = Join-Path $PSScriptRoot 'Find-DeviceInfo.ps1'
$diagramScript  = Join-Path $PSScriptRoot 'New-NetworkDiagram.ps1'
$monitorScript  = Join-Path $PSScriptRoot 'Watch-Network.ps1'
$internetScript = Join-Path $PSScriptRoot 'Get-InternetInfo.ps1'
$alertScript    = Join-Path $PSScriptRoot 'Send-NetworkAlert.ps1'

if ($SpeedTest -and $NoSpeedTest) {
    throw '-SpeedTest と -NoSpeedTest は同時に指定できません。'
}
if ($SpeedTest -and $NoExternalServices) {
    throw '速度測定には外部通信が必要です。-SpeedTest と -NoExternalServices は同時に指定できません。'
}
if ($Notify -and $NoExternalServices) {
    throw '通知には外部通信が必要な場合があります。-Notify と -NoExternalServices は同時に指定できません。'
}
$allowExternal = [bool](($ExternalChecks -or $SpeedTest) -and -not $NoExternalServices)

if ($Monitor) {
    Write-Host ''
    Write-Host '===================================' -ForegroundColor Magenta
    Write-Host ' モニタモード（連続 ping 監視）' -ForegroundColor Magenta
    Write-Host '===================================' -ForegroundColor Magenta
    $dataPath = Join-Path $PSScriptRoot '..\output\network-data.json'
    $hasData = Test-Path $dataPath
    $monitorArgs = @{
        DurationSec        = $MonitorDuration
        NoOpen             = [bool]($hasData -or $NoOpen)
        NoExternalServices = [bool](-not $allowExternal)
    }
    & $monitorScript @monitorArgs
    if ($hasData) {
        Write-Host ''
        Write-Host 'モニタ結果を統合レポートに反映しています...' -ForegroundColor Cyan
        $diagramArgs = @{ NoExternalDownloads = [bool](-not $allowExternal) }
        & $diagramScript @diagramArgs
        if (-not $NoOpen) {
            $reportPath = (Resolve-Path (Join-Path $PSScriptRoot '..\output\diagram.html')).Path
            Start-Process $reportPath
        }
    }
    return
}

if ($PublicReport) {
    $dataPath = Join-Path $PSScriptRoot '..\output\network-data.json'
    if (-not (Test-Path $dataPath)) {
        throw '公開用レポートの元データがありません。先に [2] 詳細LAN調査を実行してください。'
    }
    Write-Host ''
    Write-Host '===================================' -ForegroundColor Magenta
    Write-Host ' 公開用・仮名化レポートの生成' -ForegroundColor Magenta
    Write-Host '===================================' -ForegroundColor Magenta
    & $diagramScript -PublicReport -NoExternalDownloads -NoHistory
    $publicPath = (Resolve-Path (Join-Path $PSScriptRoot '..\output\diagram-public.html')).Path
    Write-Host "公開前に内容を目視確認してください: $publicPath" -ForegroundColor Yellow
    if (-not $NoOpen) {
        try { Start-Process $publicPath } catch { Write-Host '[!] ブラウザを開けませんでした。上記ファイルを直接開いてください。' -ForegroundColor Yellow }
    }
    return
}

$diagArgs = @{
    NoExternalServices = [bool](-not $allowExternal)
}
if ($SpeedTest) {
    $diagArgs.SpeedTest = $true
    $diagArgs.SpeedTestConnections = $SpeedTestConnections
    $diagArgs.SpeedTestMaxMB = $SpeedTestMaxMB
    $diagArgs.SpeedTestUploadMB = $SpeedTestUploadMB
}
if ($LanSpeedPath) {
    $diagArgs.LanSpeedPath = $LanSpeedPath
    $diagArgs.LanSpeedMB = $LanSpeedMB
}

if ($PSCmdlet.ParameterSetName -eq 'Basic') {
    Write-Host ''
    Write-Host '===================================' -ForegroundColor Magenta
    Write-Host ' 基本診断（LAN 全探索なし）' -ForegroundColor Magenta
    Write-Host '===================================' -ForegroundColor Magenta
    if (-not $allowExternal) {
        Write-Host '外部サービスには通信しません。' -ForegroundColor DarkGray
    }
    if ($SpeedTest) {
        Write-Host "Cloudflare への速度測定を行います（最大 約 $($SpeedTestMaxMB + $SpeedTestUploadMB) MB）。" -ForegroundColor Yellow
    }
    & $diagnoseScript @diagArgs
    if ($Notify -and (Test-Path $alertScript)) {
        try { & $alertScript } catch { Write-Host "[!] 通知の判定に失敗: $_" -ForegroundColor Yellow }
    }
    return
}

# Detailed モード: Private プロファイルの物理 NIC と RFC1918 /22～/30 のみ。
$scanTargets = @(Get-SafeScanTargets -RequestedInterfaceIndex $ScanInterfaceIndex)
if ($scanTargets.Count -eq 0) {
    throw '安全に調査できる LAN がありません。ネットワークの種類を「プライベート」にし、物理 NIC の RFC1918 IPv4 (/22～/30) を使用してください。'
}
$totalHosts = [int](($scanTargets | Measure-Object -Property hostCount -Sum).Sum)
if ($totalHosts -gt $MaxScanHosts) {
    throw "調査候補が合計 $totalHosts 台で上限 $MaxScanHosts 台を超えます。-ScanInterfaceIndex で自分が管理する NIC を1つ選んでください。"
}
if (-not (Confirm-ActiveScan -Targets $scanTargets -AllowExternal $allowExternal -IncludeSpeedTest ([bool]$SpeedTest) `
            -DownloadMB $SpeedTestMaxMB -UploadMB $SpeedTestUploadMB -Approved:$ApproveActiveScan)) {
    Write-Host '調査をキャンセルしました。設定変更や通信は行っていません。' -ForegroundColor Yellow
    return
}

$psMajor = $PSVersionTable.PSVersion.Major
if ($psMajor -lt 7) {
    Write-Host '[!] PowerShell 5.1 では機器プローブが直列になるため、時間がかかることがあります。' -ForegroundColor Yellow
}

$doInternetInfo = $allowExternal -and -not $SkipInternetInfo
$totalSteps = if ($doInternetInfo) { 5 } else { 4 }
$stepNum = 1

Write-Host "`n===================================" -ForegroundColor Magenta
Write-Host " Step $stepNum/$totalSteps : ネットワーク診断" -ForegroundColor Magenta
Write-Host '===================================' -ForegroundColor Magenta
& $diagnoseScript @diagArgs
$stepNum++

Write-Host "`n===================================" -ForegroundColor Magenta
Write-Host " Step $stepNum/$totalSteps : ネットワーク情報収集" -ForegroundColor Magenta
Write-Host '===================================' -ForegroundColor Magenta
$collectArgs = @{
    ScanSubnet         = $true
    ScanInterfaceIndex = @($scanTargets.interfaceIndex | Sort-Object -Unique)
    ResolveHostnames   = $allowExternal
    IncludeTraceroute  = $allowExternal
}
& $collectScript @collectArgs
$stepNum++

$allowedCidrs = @($scanTargets.cidr | Sort-Object -Unique)
Write-Host "`n===================================" -ForegroundColor Magenta
Write-Host " Step $stepNum/$totalSteps : 機器特定$(if ($Light) { ' (軽量)' })" -ForegroundColor Magenta
Write-Host '===================================' -ForegroundColor Magenta
$identifyArgs = @{
    AllowedCidrs        = $allowedCidrs
    NoExternalDownloads = [bool](-not $allowExternal)
}
if ($Light) { $identifyArgs.Light = $true }
& $identifyScript @identifyArgs
$stepNum++

if ($doInternetInfo) {
    Write-Host "`n===================================" -ForegroundColor Magenta
    Write-Host " Step $stepNum/$totalSteps : インターネット側の情報取得" -ForegroundColor Magenta
    Write-Host '===================================' -ForegroundColor Magenta
    if (Test-Path $internetScript) {
        try {
            $internetArgs = @{}
            if ($Light) { $internetArgs.SkipRdap = $true }
            & $internetScript @internetArgs
        } catch {
            Write-Host '[!] インターネット側の情報取得に失敗しました。ほかの情報でレポートを生成します。' -ForegroundColor Yellow
            Write-Host "    $_" -ForegroundColor DarkGray
        }
    }
    $stepNum++
}

Write-Host "`n===================================" -ForegroundColor Magenta
Write-Host " Step $stepNum/$totalSteps : レポート生成$(if ($Light) { ' (軽量)' })" -ForegroundColor Magenta
Write-Host '===================================' -ForegroundColor Magenta
$diagramArgs = @{ NoExternalDownloads = [bool](-not $allowExternal) }
if ($Light) { $diagramArgs.Light = $true }
& $diagramScript @diagramArgs

if ($Notify -and (Test-Path $alertScript)) {
    try { & $alertScript } catch { Write-Host "[!] 通知の判定に失敗: $_" -ForegroundColor Yellow }
}

$htmlPath = (Resolve-Path (Join-Path $PSScriptRoot '..\output\diagram.html')).Path
Write-Host "`n完了しました: $htmlPath" -ForegroundColor Green
if (-not $NoOpen) {
    try { Start-Process $htmlPath } catch { Write-Host '[!] ブラウザを開けませんでした。上記ファイルを直接開いてください。' -ForegroundColor Yellow }
}
