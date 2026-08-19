<#
.SYNOPSIS
    診断で見つかった設定の不備を、確認のうえで安全に修正する。

.DESCRIPTION
    network-health.json から PC 側で機械的に修正できる項目だけを抽出する。
    実行内容は型付きの操作データとして保持し、許可リストにない操作や値は拒否する。
    管理者権限が必要な場合は、SHA-256 で改ざんを検知する一時プランを同じスクリプトへ渡す。

    ルーター設定、Wi-Fi チャネル、機器交換など判断を伴う作業は対象外。

.PARAMETER WhatIfOnly
    実行せず、修正できる項目と実行内容だけを表示する

.PARAMETER Yes
    確認を省いて適用する（自動化向け）

.PARAMETER Rollback
    直近の安全なバックアップから設定を戻す

.EXAMPLE
    .\Repair-NetworkSetting.ps1 -WhatIfOnly

.EXAMPLE
    .\Repair-NetworkSetting.ps1
#>

[CmdletBinding()]
param(
    [string]$HealthPath = "$PSScriptRoot\..\output\network-health.json",
    [string]$OutputDir  = "$PSScriptRoot\..\output",
    [switch]$WhatIfOnly,
    [switch]$Yes,
    [switch]$Rollback,
    # 内部用: 昇格後に検証済みの型付きプランを適用する
    [string]$ApplyPlan,
    [string]$PlanHash
)

$ErrorActionPreference = 'Continue'

function Write-Step  { param([string]$M) Write-Host "[*] $M" -ForegroundColor Cyan }
function Write-Ok    { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn2 { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-TrustedNetworkingModules {
    $windowsDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $moduleRoot = Join-Path $windowsDir 'System32\WindowsPowerShell\v1.0\Modules'
    foreach ($moduleName in @('NetAdapter', 'DnsClient', 'NetTCPIP')) {
        $manifest = Join-Path $moduleRoot "$moduleName\$moduleName.psd1"
        if (-not [IO.File]::Exists($manifest)) { throw "Windows 標準モジュールが見つかりません: $moduleName" }
        Import-Module -Name $manifest -Force -ErrorAction Stop
    }
}

function Test-SafeActionText {
    param([string]$Value, [int]$MaxLength = 256)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $MaxLength) { return $false }
    return ($Value -notmatch '[\x00-\x1F\x7F]')
}

function ConvertTo-SafeDisplayText {
    param($Value, [int]$MaxLength = 256)
    $text = ([string]$Value -replace '[\x00-\x1F\x7F]', ' ').Trim()
    if ($text.Length -gt $MaxLength) { return $text.Substring(0, $MaxLength) + '…' }
    return $text
}

function Test-RepairAction {
    param($Action)
    if ($null -eq $Action -or -not (Test-SafeActionText -Value ([string]$Action.type) -MaxLength 64)) {
        return $false
    }

    switch ([string]$Action.type) {
        'TcpAutoTuning' {
            return ([string]$Action.level -in @('disabled', 'highlyrestricted', 'restricted', 'normal', 'experimental'))
        }
        'TcpRss' {
            return ([string]$Action.state -in @('enabled', 'disabled'))
        }
        'AdapterBinding' {
            return (
                (Test-SafeActionText -Value ([string]$Action.adapterName)) -and
                [string]$Action.componentId -eq 'ms_tcpip6' -and
                $Action.enabled -is [bool]
            )
        }
        'DnsReset' {
            return (Test-SafeActionText -Value ([string]$Action.adapterName))
        }
        'DnsSet' {
            if (-not (Test-SafeActionText -Value ([string]$Action.adapterName))) { return $false }
            $addresses = @($Action.addresses)
            if ($addresses.Count -lt 1 -or $addresses.Count -gt 8) { return $false }
            foreach ($addressText in $addresses) {
                $address = $null
                if (-not [System.Net.IPAddress]::TryParse([string]$addressText, [ref]$address)) { return $false }
                if ($address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
            }
            return $true
        }
        'InterfaceMetric' {
            if (-not (Test-SafeActionText -Value ([string]$Action.adapterName))) { return $false }
            if ([string]$Action.mode -eq 'Automatic') { return $true }
            if ([string]$Action.mode -ne 'Manual') { return $false }
            $metric = 0
            return ([int]::TryParse([string]$Action.metric, [ref]$metric) -and $metric -ge 1 -and $metric -le 9999)
        }
        'AdapterAdvancedDisplay' {
            return (
                (Test-SafeActionText -Value ([string]$Action.adapterName)) -and
                [string]$Action.registryKeyword -eq '*SpeedDuplex' -and
                (Test-SafeActionText -Value ([string]$Action.displayValue))
            )
        }
        'AdapterAdvancedRegistry' {
            if (-not (Test-SafeActionText -Value ([string]$Action.adapterName))) { return $false }
            if ([string]$Action.registryKeyword -ne '*ReceiveBuffers') { return $false }
            $registryValue = 0
            return ([int]::TryParse([string]$Action.registryValue, [ref]$registryValue) -and $registryValue -ge 1 -and $registryValue -le 65535)
        }
        default { return $false }
    }
}

function Get-RepairActionDescription {
    param($Action)
    switch ([string]$Action.type) {
        'TcpAutoTuning' { return "TCP 自動チューニングを $($Action.level) に設定" }
        'TcpRss' { return "TCP RSS を $($Action.state) に設定" }
        'AdapterBinding' { return "$($Action.adapterName) の IPv6 バインドを $(if ($Action.enabled) { '有効化' } else { '無効化' })" }
        'DnsReset' { return "$($Action.adapterName) の DNS を自動取得へ戻す" }
        'DnsSet' { return "$($Action.adapterName) の DNS を $(@($Action.addresses) -join ', ') に設定" }
        'InterfaceMetric' {
            if ([string]$Action.mode -eq 'Automatic') { return "$($Action.adapterName) の IPv4 メトリックを自動へ戻す" }
            return "$($Action.adapterName) の IPv4 メトリックを $($Action.metric) に設定"
        }
        'AdapterAdvancedDisplay' { return "$($Action.adapterName) の速度/デュプレックスを $($Action.displayValue) に設定" }
        'AdapterAdvancedRegistry' { return "$($Action.adapterName) の受信バッファを $($Action.registryValue) に設定" }
        default { return '許可されていない操作' }
    }
}

function Invoke-RepairAction {
    param([Parameter(Mandatory)]$Action)
    if (-not (Test-RepairAction -Action $Action)) { throw '許可されていない修復操作です' }

    switch ([string]$Action.type) {
        'TcpAutoTuning' {
            $netsh = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\netsh.exe'
            & $netsh 'int' 'tcp' 'set' 'global' "autotuninglevel=$($Action.level)" | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "netsh が終了コード $LASTEXITCODE を返しました" }
        }
        'TcpRss' {
            $netsh = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\netsh.exe'
            & $netsh 'int' 'tcp' 'set' 'global' "rss=$($Action.state)" | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "netsh が終了コード $LASTEXITCODE を返しました" }
        }
        'AdapterBinding' {
            NetAdapter\Get-NetAdapter -Name ([string]$Action.adapterName) -ErrorAction Stop | Out-Null
            if ($Action.enabled) {
                NetAdapter\Enable-NetAdapterBinding -Name ([string]$Action.adapterName) -ComponentID 'ms_tcpip6' -ErrorAction Stop | Out-Null
            } else {
                NetAdapter\Disable-NetAdapterBinding -Name ([string]$Action.adapterName) -ComponentID 'ms_tcpip6' -ErrorAction Stop | Out-Null
            }
        }
        'DnsReset' {
            DnsClient\Get-DnsClientServerAddress -InterfaceAlias ([string]$Action.adapterName) -AddressFamily IPv4 -ErrorAction Stop | Out-Null
            DnsClient\Set-DnsClientServerAddress -InterfaceAlias ([string]$Action.adapterName) -ResetServerAddresses -ErrorAction Stop
        }
        'DnsSet' {
            DnsClient\Get-DnsClientServerAddress -InterfaceAlias ([string]$Action.adapterName) -AddressFamily IPv4 -ErrorAction Stop | Out-Null
            DnsClient\Set-DnsClientServerAddress -InterfaceAlias ([string]$Action.adapterName) -ServerAddresses @($Action.addresses) -ErrorAction Stop
        }
        'InterfaceMetric' {
            NetTCPIP\Get-NetIPInterface -InterfaceAlias ([string]$Action.adapterName) -AddressFamily IPv4 -ErrorAction Stop | Out-Null
            if ([string]$Action.mode -eq 'Automatic') {
                NetTCPIP\Set-NetIPInterface -InterfaceAlias ([string]$Action.adapterName) -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction Stop
            } else {
                NetTCPIP\Set-NetIPInterface -InterfaceAlias ([string]$Action.adapterName) -AddressFamily IPv4 -InterfaceMetric ([int]$Action.metric) -ErrorAction Stop
            }
        }
        'AdapterAdvancedDisplay' {
            $property = @(NetAdapter\Get-NetAdapterAdvancedProperty -Name ([string]$Action.adapterName) -ErrorAction Stop |
                Where-Object { $_.RegistryKeyword -eq '*SpeedDuplex' })[0]
            if (-not $property) { throw '速度/デュプレックス設定が見つかりません' }
            $validValues = @($property.ValidDisplayValues | ForEach-Object { [string]$_ })
            if ($validValues -notcontains [string]$Action.displayValue) { throw 'ドライバーが受け付けない速度/デュプレックス値です' }
            NetAdapter\Set-NetAdapterAdvancedProperty `
                -Name ([string]$Action.adapterName) `
                -DisplayName ([string]$property.DisplayName) `
                -DisplayValue ([string]$Action.displayValue) `
                -ErrorAction Stop
        }
        'AdapterAdvancedRegistry' {
            $property = @(NetAdapter\Get-NetAdapterAdvancedProperty -Name ([string]$Action.adapterName) -ErrorAction Stop |
                Where-Object { $_.RegistryKeyword -eq '*ReceiveBuffers' })[0]
            if (-not $property) { throw '受信バッファ設定が見つかりません' }
            $value = [int]$Action.registryValue
            $minimum = 1
            $maximum = 65535
            if ($null -ne $property.NumericParameterMinValue) { $minimum = [int]$property.NumericParameterMinValue }
            if ($null -ne $property.NumericParameterMaxValue) { $maximum = [int]$property.NumericParameterMaxValue }
            if ($value -lt $minimum -or $value -gt $maximum) { throw "受信バッファ値がドライバー範囲外です ($minimum-$maximum)" }
            NetAdapter\Set-NetAdapterAdvancedProperty `
                -Name ([string]$Action.adapterName) `
                -RegistryKeyword '*ReceiveBuffers' `
                -RegistryValue $value `
                -ErrorAction Stop
        }
    }
}

function Invoke-RepairActions {
    param([array]$Actions)
    try { Import-TrustedNetworkingModules } catch {
        Write-Warn2 "Windows 標準ネットワークモジュールを読み込めません: $($_.Exception.Message)"
        return $false
    }
    $allSucceeded = $true
    foreach ($action in @($Actions)) {
        try {
            Write-Step (Get-RepairActionDescription -Action $action)
            Invoke-RepairAction -Action $action
        } catch {
            Write-Warn2 "適用に失敗しました: $($_.Exception.Message)"
            $allSucceeded = $false
        }
    }
    return $allSucceeded
}

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Read-ValidatedRepairPlan {
    param([string]$Path, [string]$ExpectedHash)
    if ($ExpectedHash -notmatch '^[0-9A-Fa-f]{64}$') { throw '修復プランのハッシュ形式が不正です' }

    $planRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) 'NetworkTopologyMapper\repair-plans'))
    $fullPath = [IO.Path]::GetFullPath($Path)
    $rootPrefix = $planRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw '修復プランが所定の一時フォルダ外にあります'
    }
    if (-not [IO.File]::Exists($fullPath)) { throw '修復プランが見つかりません' }

    $bytes = [IO.File]::ReadAllBytes($fullPath)
    if ($bytes.Length -lt 2 -or $bytes.Length -gt 1048576) { throw '修復プランのサイズが不正です' }
    $actualHash = Get-Sha256Hex -Bytes $bytes
    if ($actualHash -ne $ExpectedHash.ToUpperInvariant()) { throw '修復プランが作成後に変更されています' }

    $json = [Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    $plan = $json | ConvertFrom-Json
    if ([int]$plan.schemaVersion -ne 1) { throw '未対応の修復プラン形式です' }
    if ([string]$plan.purpose -notin @('Apply', 'Rollback')) { throw '修復プランの用途が不正です' }
    $actions = @($plan.actions)
    if ($actions.Count -lt 1 -or $actions.Count -gt 20) { throw '修復操作の件数が不正です' }
    foreach ($action in $actions) {
        if (-not (Test-RepairAction -Action $action)) { throw '修復プランに許可されていない操作が含まれています' }
    }
    return $plan
}

function Invoke-ActionPlan {
    param([array]$Actions, [ValidateSet('Apply', 'Rollback')][string]$Purpose)
    if (@($Actions).Count -eq 0) { return $true }
    if (@($Actions).Count -gt 20) { Write-Warn2 '一度に適用できる修復操作は 20 件までです'; return $false }

    foreach ($action in @($Actions)) {
        if (-not (Test-RepairAction -Action $action)) {
            Write-Warn2 '安全性を確認できない操作が含まれるため中止しました'
            return $false
        }
    }

    if (Test-IsAdmin) { return (Invoke-RepairActions -Actions $Actions) }

    $planDir = Join-Path ([IO.Path]::GetTempPath()) 'NetworkTopologyMapper\repair-plans'
    if (-not (Test-Path $planDir)) { New-Item -ItemType Directory -Path $planDir -Force | Out-Null }
    $planPath = Join-Path $planDir ("repair-$([guid]::NewGuid().ToString('N')).json")
    $planObject = [PSCustomObject]@{
        schemaVersion = 1
        purpose       = $Purpose
        createdAt     = (Get-Date).ToString('o')
        actions       = @($Actions)
    }
    $json = $planObject | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($planPath, $json, (New-Object Text.UTF8Encoding($true)))
    $hash = Get-Sha256Hex -Bytes ([IO.File]::ReadAllBytes($planPath))

    try {
        $exe = (Get-Process -Id $PID).Path
        if (-not $exe) {
            $exe = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)) 'System32\WindowsPowerShell\v1.0\powershell.exe'
        }
        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$PSCommandPath`"",
            '-ApplyPlan', "`"$planPath`"",
            '-PlanHash', $hash
        )
        $process = Start-Process `
            -FilePath $exe `
            -ArgumentList $arguments `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru `
            -ErrorAction Stop
        return ($process.ExitCode -eq 0)
    } catch {
        Write-Warn2 "管理者権限での実行に失敗しました（キャンセルされた可能性）: $($_.Exception.Message)"
        return $false
    } finally {
        if ([IO.File]::Exists($planPath)) { [IO.File]::Delete($planPath) }
    }
}

# 昇格後の内部実行。ファイル内容は一度だけ読み、ハッシュと全操作を検証してから適用する。
if ($ApplyPlan -or $PlanHash) {
    try {
        if (-not $ApplyPlan -or -not $PlanHash) { throw '修復プランとハッシュの両方が必要です' }
        if (-not (Test-IsAdmin)) { throw '管理者権限がありません' }
        $validatedPlan = Read-ValidatedRepairPlan -Path $ApplyPlan -ExpectedHash $PlanHash
        if (Invoke-RepairActions -Actions @($validatedPlan.actions)) { exit 0 }
        exit 1
    } catch {
        Write-Error $_.Exception.Message
        exit 1
    }
}

# ==========================================
# ロールバック
# ==========================================
if ($Rollback) {
    $backups = @(Get-ChildItem -Path $OutputDir -Filter 'setting-backup-*.json' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    if ($backups.Count -eq 0) { Write-Warn2 '戻せるバックアップがありません'; return }

    if ($backups[0].Length -lt 2 -or $backups[0].Length -gt 1048576) {
        Write-Warn2 'バックアップのサイズが不正なため読み込みません'
        return
    }
    try { $backup = Get-Content $backups[0].FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch {
        Write-Warn2 "バックアップを読み込めません: $($_.Exception.Message)"
        return
    }
    $backupSchema = 0
    if (-not [int]::TryParse([string]$backup.schemaVersion, [ref]$backupSchema) -or
        $backupSchema -ne 2 -or [string]$backup.backupKind -ne 'NetworkTopologyMapperSettings') {
        Write-Warn2 '旧形式または不明なバックアップは、コマンド文字列を含むため安全上の理由で実行しません'
        return
    }

    $rollbackActions = @()
    $backupItems = @($backup.items)
    if ($backupItems.Count -lt 1 -or $backupItems.Count -gt 20) {
        Write-Warn2 'バックアップ内の復元操作数が不正です'
        return
    }
    foreach ($item in $backupItems) {
        if (-not (Test-RepairAction -Action $item.rollbackAction)) {
            Write-Warn2 'バックアップに許可されていない操作が含まれるため中止しました'
            return
        }
        $rollbackActions += $item.rollbackAction
    }
    if ($rollbackActions.Count -eq 0) { Write-Warn2 'バックアップに復元操作がありません'; return }

    Write-Step "バックアップから復元します: $($backups[0].Name)（取得 $($backup.timestamp)）"
    foreach ($item in @($backup.items)) {
        Write-Host "  - $(ConvertTo-SafeDisplayText $item.label): $(ConvertTo-SafeDisplayText $item.oldValue) に戻す" -ForegroundColor Gray
    }
    if ($WhatIfOnly) { Write-Host '（-WhatIfOnly のため実行しません）' -ForegroundColor DarkGray; return }
    if (-not $Yes) {
        $answer = Read-Host '復元する場合は y を入力してください [y/N]'
        if ($answer.Trim().ToUpperInvariant() -ne 'Y') { Write-Host '中止しました' -ForegroundColor Gray; return }
    }
    if (Invoke-ActionPlan -Actions $rollbackActions -Purpose Rollback) {
        Write-Ok '復元しました。診断を再実行して確認してください'
    } else {
        Write-Warn2 '一部または全部の復元に失敗しました'
    }
    return
}

# ==========================================
# 診断結果から、直せる項目を洗い出す
# ==========================================
if (-not (Test-Path $HealthPath)) {
    throw "診断結果が見つかりません: $HealthPath。先に Test-NetworkHealth.ps1 を実行してください。"
}
$health = Get-Content $HealthPath -Raw -Encoding UTF8 | ConvertFrom-Json
function Get-Step { param([string]$Name) return (@($health.results | Where-Object { $_.step -eq $Name })[0]) }

$fixes = @()
$validAutotuneLevels = @('disabled', 'highlyrestricted', 'restricted', 'normal', 'experimental')

# TCP 受信ウィンドウ自動チューニング / RSS
$tcpStep = Get-Step 'TCP/IP スタック設定'
if ($tcpStep -and $tcpStep.metrics) {
    $autotune = ([string]$tcpStep.metrics.autoTuningLevel).ToLowerInvariant()
    $rss = ([string]$tcpStep.metrics.rss).ToLowerInvariant()
    if ($autotune -in $validAutotuneLevels -and $autotune -ne 'normal') {
        $fixes += [PSCustomObject]@{
            id = 'autotune'; label = 'TCP 受信ウィンドウ自動チューニング'
            current = $autotune; target = 'normal'
            why = '無効だと高速回線でも受信速度が頭打ちになることがあります'
            action = [PSCustomObject]@{ type = 'TcpAutoTuning'; level = 'normal' }
            rollbackAction = [PSCustomObject]@{ type = 'TcpAutoTuning'; level = $autotune }
        }
    }
    if ($rss -eq 'disabled') {
        $fixes += [PSCustomObject]@{
            id = 'rss'; label = '受信側スケーリング (RSS)'
            current = $rss; target = 'enabled'
            why = '無効だと受信処理が 1 コアに偏り、高速回線で頭打ちになることがあります'
            action = [PSCustomObject]@{ type = 'TcpRss'; state = 'enabled' }
            rollbackAction = [PSCustomObject]@{ type = 'TcpRss'; state = 'disabled' }
        }
    }
}

# NIC の IPv6 バインド
$v6Step = Get-Step 'IPv6 / WAN経路'
if ($v6Step -and $v6Step.status -ne 'pass' -and "$($v6Step.detail)" -match 'IPv6 が無効|バインド') {
    $adapterName = if ($health.summary -and $health.summary.primaryAdapter) { [string]$health.summary.primaryAdapter.name } else { $null }
    if (Test-SafeActionText -Value $adapterName) {
        try {
            $binding = Get-NetAdapterBinding -Name $adapterName -ComponentID 'ms_tcpip6' -ErrorAction Stop
            if ($binding -and -not $binding.Enabled) {
                $fixes += [PSCustomObject]@{
                    id = 'ipv6bind'; label = "$adapterName の IPv6 を有効化"
                    current = '無効'; target = '有効'
                    why = 'IPv6 が無効だと IPoE を利用できない場合があります'
                    action = [PSCustomObject]@{ type = 'AdapterBinding'; adapterName = $adapterName; componentId = 'ms_tcpip6'; enabled = $true }
                    rollbackAction = [PSCustomObject]@{ type = 'AdapterBinding'; adapterName = $adapterName; componentId = 'ms_tcpip6'; enabled = $false }
                }
            }
        } catch { }
    }
}

# 応答しない DNS サーバが設定されたインターフェイス
$dnsStep = Get-Step 'DNS 名前解決'
$deadDnsIfs = @()
if ($dnsStep -and $dnsStep.metrics -and $dnsStep.metrics.servers) {
    foreach ($server in @($dnsStep.metrics.servers)) {
        if (-not $server.reachable -and (Test-SafeActionText -Value ([string]$server.interfaceAlias))) {
            $deadDnsIfs += [string]$server.interfaceAlias
        }
    }
}
foreach ($alias in (@($deadDnsIfs) | Sort-Object -Unique)) {
    $currentAddresses = @((Get-DnsClientServerAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
        Where-Object { $_ })
    $validAddresses = @($currentAddresses | Where-Object {
        $parsedAddress = $null
        [System.Net.IPAddress]::TryParse([string]$_, [ref]$parsedAddress) -and
        $parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    })
    if ($validAddresses.Count -eq 0 -or $validAddresses.Count -ne $currentAddresses.Count) { continue }
    $fixes += [PSCustomObject]@{
        id = "dns-$alias"; label = "$alias の DNS 設定を外す"
        current = ($validAddresses -join ', '); target = '自動取得に戻す'
        why = '応答しない DNS サーバを待つことで、名前解決が遅くなる可能性があります'
        action = [PSCustomObject]@{ type = 'DnsReset'; adapterName = $alias }
        rollbackAction = [PSCustomObject]@{ type = 'DnsSet'; adapterName = $alias; addresses = @($validAddresses) }
    }
}

# 到達できないゲートウェイが優先されている場合は、インターフェイス優先度を下げる
$routeStep = Get-Step '経路の重複'
if ($routeStep -and $routeStep.status -eq 'fail' -and $routeStep.metrics -and $routeStep.metrics.gateways) {
    foreach ($gateway in @($routeStep.metrics.gateways)) {
        $routeAlias = [string]$gateway.interfaceAlias
        if ($gateway.reachable -or -not (Test-SafeActionText -Value $routeAlias)) { continue }
        try {
            $interface = @(Get-NetIPInterface -InterfaceAlias $routeAlias -AddressFamily IPv4 -ErrorAction Stop)[0]
            if (-not $interface) { continue }
            $rollbackMetric = if ([string]$interface.AutomaticMetric -eq 'Enabled') {
                [PSCustomObject]@{ type = 'InterfaceMetric'; adapterName = $routeAlias; mode = 'Automatic' }
            } else {
                [PSCustomObject]@{ type = 'InterfaceMetric'; adapterName = $routeAlias; mode = 'Manual'; metric = [int]$interface.InterfaceMetric }
            }
            if (-not (Test-RepairAction -Action $rollbackMetric)) { continue }
            $fixes += [PSCustomObject]@{
                id = "metric-$routeAlias"; label = "$routeAlias の優先度を下げる"
                current = "メトリック $($interface.InterfaceMetric)"; target = 'メトリック 9999'
                why = "到達できないゲートウェイ $(ConvertTo-SafeDisplayText $gateway.gateway) の待ち時間を避けます"
                action = [PSCustomObject]@{ type = 'InterfaceMetric'; adapterName = $routeAlias; mode = 'Manual'; metric = 9999 }
                rollbackAction = $rollbackMetric
            }
        } catch { }
    }
}

# 有線 NIC の速度/デュプレックスと受信バッファ
$linkStep = Get-Step '有線リンク速度/NIC設定'
if ($linkStep -and $linkStep.metrics) {
    foreach ($row in @($linkStep.metrics.adapters)) {
        $nicName = [string]$row.name
        if (-not (Test-SafeActionText -Value $nicName)) { continue }
        $advanced = @()
        try { $advanced = @(Get-NetAdapterAdvancedProperty -Name $nicName -ErrorAction Stop) } catch { continue }

        $speedProperty = @($advanced | Where-Object { $_.RegistryKeyword -eq '*SpeedDuplex' })[0]
        if ($speedProperty) {
            $currentDisplay = [string]$speedProperty.DisplayValue
            $autoDisplay = @($speedProperty.ValidDisplayValues | Where-Object { [string]$_ -match 'Auto|オート|自動' } | Select-Object -First 1)
            if ($currentDisplay -and $currentDisplay -notmatch 'Auto|オート|自動' -and $autoDisplay.Count -gt 0 -and
                (Test-SafeActionText -Value $currentDisplay) -and (Test-SafeActionText -Value ([string]$autoDisplay[0]))) {
                $fixes += [PSCustomObject]@{
                    id = "duplex-$nicName"; label = "$nicName の速度/デュプレックスを自動に戻す"
                    current = $currentDisplay; target = [string]$autoDisplay[0]
                    why = '手動固定が対向機器と食い違うと、通信速度や安定性が低下します'
                    action = [PSCustomObject]@{ type = 'AdapterAdvancedDisplay'; adapterName = $nicName; registryKeyword = '*SpeedDuplex'; displayValue = [string]$autoDisplay[0] }
                    rollbackAction = [PSCustomObject]@{ type = 'AdapterAdvancedDisplay'; adapterName = $nicName; registryKeyword = '*SpeedDuplex'; displayValue = $currentDisplay }
                }
            }
        }

        if ($row.rxBufferIncreaseRecommended) {
            $bufferProperty = @($advanced | Where-Object { $_.RegistryKeyword -eq '*ReceiveBuffers' })[0]
            if ($bufferProperty) {
                $currentBuffer = 0
                $maximumBuffer = 0
                $hasCurrent = [int]::TryParse([string](@($bufferProperty.RegistryValue)[0]), [ref]$currentBuffer)
                $hasMaximum = [int]::TryParse([string]$bufferProperty.NumericParameterMaxValue, [ref]$maximumBuffer)
                if ($hasCurrent -and $hasMaximum -and $currentBuffer -ge 1 -and $maximumBuffer -gt $currentBuffer -and $maximumBuffer -le 65535) {
                    $fixes += [PSCustomObject]@{
                        id = "rxbuf-$nicName"; label = "$nicName の受信バッファを増やす"
                        current = "$currentBuffer"; target = "$maximumBuffer（ドライバーの最大値）"
                        why = '受信破棄を減らせる可能性があります。適用時に数秒リンクが切れることがあります'
                        action = [PSCustomObject]@{ type = 'AdapterAdvancedRegistry'; adapterName = $nicName; registryKeyword = '*ReceiveBuffers'; registryValue = $maximumBuffer }
                        rollbackAction = [PSCustomObject]@{ type = 'AdapterAdvancedRegistry'; adapterName = $nicName; registryKeyword = '*ReceiveBuffers'; registryValue = $currentBuffer }
                    }
                }
            }
        }
    }
}

$fixes = @($fixes | Where-Object {
    (Test-RepairAction -Action $_.action) -and (Test-RepairAction -Action $_.rollbackAction)
})

if ($fixes.Count -eq 0) {
    Write-Ok '自動で直せる設定の不備は見つかりませんでした'
    Write-Host '（ルーター設定・Wi-Fi チャネル・機器交換など、判断が要るものは対象外です）' -ForegroundColor DarkGray
    return
}

Write-Host ''
Write-Host '===============================================' -ForegroundColor Magenta
Write-Host " 修正できる項目: $($fixes.Count) 件" -ForegroundColor Magenta
Write-Host '===============================================' -ForegroundColor Magenta
foreach ($fix in $fixes) {
    Write-Host ''
    Write-Host "  $(ConvertTo-SafeDisplayText $fix.label)" -ForegroundColor White
    Write-Host "    現在: $(ConvertTo-SafeDisplayText $fix.current)  →  変更後: $(ConvertTo-SafeDisplayText $fix.target)" -ForegroundColor Gray
    Write-Host "    理由: $(ConvertTo-SafeDisplayText $fix.why -MaxLength 512)" -ForegroundColor Gray
    Write-Host "    操作: $(Get-RepairActionDescription -Action $fix.action)" -ForegroundColor Cyan
}
Write-Host ''

if ($WhatIfOnly) {
    Write-Host '（-WhatIfOnly のため実行しません）' -ForegroundColor DarkGray
    return
}

if (-not $Yes) {
    Write-Host 'これらを適用しますか？ 管理者権限の確認が表示されます。' -ForegroundColor Yellow
    Write-Host '元の値は保存され、-Rollback で戻せます。NIC 設定では数秒通信が切れる場合があります。' -ForegroundColor Yellow
    $answer = Read-Host '適用する場合は y を入力してください [y/N]'
    if ($answer.Trim().ToUpperInvariant() -ne 'Y') { Write-Host '中止しました' -ForegroundColor Gray; return }
}

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$backupPath = Join-Path $OutputDir ("setting-backup-$((Get-Date).ToString('yyyyMMdd-HHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0,8)).json")
$backupObject = [PSCustomObject]@{
    schemaVersion = 2
    backupKind    = 'NetworkTopologyMapperSettings'
    timestamp     = (Get-Date).ToString('o')
    items         = @($fixes | ForEach-Object {
        [PSCustomObject]@{
            id             = $_.id
            label          = $_.label
            oldValue       = $_.current
            appliedAction  = $_.action
            rollbackAction = $_.rollbackAction
        }
    })
}
$backupObject | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $backupPath -Encoding UTF8
Write-Ok "変更前の値を保存しました: $backupPath"

$succeeded = Invoke-ActionPlan -Actions @($fixes.action) -Purpose Apply
Write-Host ''
if ($succeeded) {
    Write-Ok '適用しました'
    Write-Host '  効果を確認するには、診断を再実行してください:' -ForegroundColor Cyan
    Write-Host '    .\Run-NetworkMapper.ps1 -DiagnoseOnly' -ForegroundColor White
    Write-Host '  元に戻す場合:' -ForegroundColor Cyan
    Write-Host '    .\Repair-NetworkSetting.ps1 -Rollback' -ForegroundColor White
} else {
    Write-Warn2 '一部または全部の変更に失敗しました。上のメッセージを確認してください'
    Write-Host '  元に戻す場合: .\Repair-NetworkSetting.ps1 -Rollback' -ForegroundColor Cyan
}
