<#
.SYNOPSIS
    Windows環境のネットワーク情報を収集してJSON形式で出力します。

.DESCRIPTION
    ローカルアダプタ、ルーティングテーブル、ARP近隣、DNS設定、
    オプションでサブネットスキャンとtracerouteを実施し、
    ネットワークトポロジ生成用の構造化データを出力します。

.PARAMETER OutputPath
    出力JSONファイルのパス（デフォルト: .\output\network-data.json）

.PARAMETER ScanSubnet
    指定するとローカルサブネットのpingスキャンを実施（時間がかかる）

.PARAMETER ScanTimeout
    pingスキャンのタイムアウト（ミリ秒、デフォルト: 500）

.PARAMETER ScanThrottle
    並列ping実行数（デフォルト: 50）

.PARAMETER IncludeTraceroute
    指定するとデフォルトゲートウェイ経由のtracerouteを実施

.PARAMETER TracerouteTarget
    tracerouteのターゲット（デフォルト: 8.8.8.8）

.PARAMETER ResolveHostnames
    指定すると発見ホストの逆引きDNSを実施

.EXAMPLE
    .\Collect-NetworkInfo.ps1
    基本情報のみ収集

.EXAMPLE
    .\Collect-NetworkInfo.ps1 -ScanSubnet -ResolveHostnames -IncludeTraceroute
    フル収集（サブネットスキャン + 逆引き + traceroute）

.NOTES
    管理者権限なしで動作可能ですが、一部情報（一部のWMI）は管理者で実行するとより詳細になります。
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\..\output\network-data.json",
    [switch]$ScanSubnet,
    # 能動スキャンを許可するアダプタ。-ScanSubnet と併用時は必須。
    [int[]]$ScanInterfaceIndex,
    [int]$ScanTimeout = 500,
    [int]$ScanThrottle = 50,
    [switch]$IncludeTraceroute,
    [string]$TracerouteTarget = "8.8.8.8",
    [switch]$ResolveHostnames,
    # 帯域の使用状況（アダプタ実測 + プロセス別の推定）を測る秒数
    [ValidateRange(1, 600)]
    [int]$BandwidthSeconds = 3,
    [switch]$SkipBandwidth
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# ==========================================
# ヘルパー関数
# ==========================================

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn2 {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

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

# ==========================================
# 1. ホスト基本情報
# ==========================================

function Get-HostMetadata {
    Write-Step "ホスト基本情報を収集中..."

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    return [ordered]@{
        timestamp     = (Get-Date).ToString("o")
        hostname      = $env:COMPUTERNAME
        domain        = if ($cs) { $cs.Domain } else { "" }
        username      = $env:USERNAME
        os            = if ($os) { "$($os.Caption) $($os.Version)" } else { "" }
        psVersion     = $PSVersionTable.PSVersion.ToString()
        isAdmin       = ([Security.Principal.WindowsPrincipal] `
                            [Security.Principal.WindowsIdentity]::GetCurrent() `
                        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

# ==========================================
# 2. ネットワークアダプタ情報
# ==========================================

function Get-AdapterInfo {
    Write-Step "ネットワークアダプタ情報を収集中..."

    try {
        $adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' })
    } catch {
        Write-Warn2 "ネットワークアダプタ情報を取得できませんでした: $($_.Exception.Message)"
        return ,@()
    }

    $result = @()

    foreach ($a in $adapters) {
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue

        $ipv4Addrs = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex `
                        -AddressFamily IPv4 -ErrorAction SilentlyContinue `
                        | ForEach-Object {
                            [ordered]@{
                                address      = $_.IPAddress
                                prefixLength = $_.PrefixLength
                                type         = $_.PrefixOrigin
                            }
                        })

        # IPv6: グローバル(GUA)とリンクローカル(fe80::)を区別して保持する。
        # IPoE 環境では GUA の有無が「v6 が実際に使えているか」の判断材料になる。
        $ipv6Addrs = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex `
                        -AddressFamily IPv6 -ErrorAction SilentlyContinue `
                        | Where-Object { $_.IPAddress -notlike 'ff*' } `
                        | ForEach-Object {
                            [ordered]@{
                                address      = $_.IPAddress
                                prefixLength = $_.PrefixLength
                                type         = $_.PrefixOrigin
                                scope        = if ($_.IPAddress -like 'fe80:*') { 'link-local' }
                                               elseif ($_.IPAddress -like 'fd*' -or $_.IPAddress -like 'fc*') { 'unique-local' }
                                               else { 'global' }
                            }
                        })

        $dns = @()
        if ($ipConfig -and $ipConfig.DNSServer) {
            $dns = @($ipConfig.DNSServer | Where-Object AddressFamily -eq 2 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
        }

        $dns6 = @()
        if ($ipConfig -and $ipConfig.DNSServer) {
            $dns6 = @($ipConfig.DNSServer | Where-Object AddressFamily -eq 23 | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
        }

        $gw = if ($ipConfig -and $ipConfig.IPv4DefaultGateway) {
            $ipConfig.IPv4DefaultGateway.NextHop
        } else { $null }

        $gw6 = if ($ipConfig -and $ipConfig.IPv6DefaultGateway) {
            $ipConfig.IPv6DefaultGateway.NextHop
        } else { $null }

        $result += [ordered]@{
            name             = $a.Name
            interfaceIndex   = $a.ifIndex
            description      = $a.InterfaceDescription
            status           = $a.Status.ToString()
            macAddress       = $a.MacAddress
            linkSpeed        = $a.LinkSpeed
            mediaType        = $a.MediaType
            connectionType   = $a.MediaConnectionState.ToString()
            ipv4Addresses    = $ipv4Addrs
            ipv4Gateway      = $gw
            dnsServers       = $dns
            ipv6Addresses    = $ipv6Addrs
            ipv6Gateway      = $gw6
            dnsServersV6     = $dns6
        }
    }

    Write-Ok "$($result.Count)個のアクティブなアダプタを検出"
    return ,$result
}

# ==========================================
# 3. ルーティングテーブル
# ==========================================

function Get-RouteInfo {
    Write-Step "ルーティングテーブルを収集中..."

    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop `
            | Where-Object { $_.NextHop -ne '0.0.0.0' -or $_.DestinationPrefix -eq '0.0.0.0/0' })
    } catch {
        Write-Warn2 "ルーティングテーブルを取得できませんでした: $($_.Exception.Message)"
        return ,@()
    }

    return ,@($routes | ForEach-Object {
        [ordered]@{
            destinationPrefix = $_.DestinationPrefix
            nextHop           = $_.NextHop
            interfaceIndex    = $_.InterfaceIndex
            interfaceAlias    = $_.InterfaceAlias
            metric            = $_.RouteMetric
            policyStore       = $_.Store.ToString()
        }
    })
}

# ==========================================
# 4. ARP近隣テーブル
# ==========================================

function Get-NeighborInfo {
    Write-Step "ARP近隣テーブルを収集中..."

    try {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop `
            | Where-Object {
                $_.State -in 'Reachable','Stale','Permanent' `
                -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' `
                -and $_.LinkLayerAddress -ne '' `
                -and $_.IPAddress -notlike '224.*' `
                -and $_.IPAddress -notlike '239.*' `
                -and $_.IPAddress -ne '255.255.255.255'
            })
    } catch {
        Write-Warn2 "ARP近隣テーブルを取得できませんでした: $($_.Exception.Message)"
        return ,@()
    }

    return ,@($neighbors | ForEach-Object {
        [ordered]@{
            ipAddress       = $_.IPAddress
            macAddress      = $_.LinkLayerAddress
            state           = $_.State.ToString()
            interfaceIndex  = $_.InterfaceIndex
            interfaceAlias  = $_.InterfaceAlias
        }
    })
}

function Get-Neighbor6Info {
    # IPv6 近隣探索(NDP)のテーブル。IPoE 環境では ARP に出ない機器がここに出ることがある。
    # マルチキャスト(ff00::/8)と未解決エントリは除外する。
    Write-Step "IPv6 近隣テーブルを収集中..."

    try {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv6 -ErrorAction Stop `
            | Where-Object {
                $_.State -in 'Reachable','Stale','Permanent' `
                -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' `
                -and $_.LinkLayerAddress -ne '' `
                -and $_.IPAddress -notlike 'ff*'
            })
    } catch {
        Write-Warn2 "IPv6 近隣テーブルを取得できませんでした: $($_.Exception.Message)"
        return ,@()
    }

    $out = @($neighbors | ForEach-Object {
        [ordered]@{
            ipAddress       = $_.IPAddress
            macAddress      = $_.LinkLayerAddress
            state           = $_.State.ToString()
            interfaceIndex  = $_.InterfaceIndex
            interfaceAlias  = $_.InterfaceAlias
            scope           = if ($_.IPAddress -like 'fe80:*') { 'link-local' } else { 'global' }
        }
    })
    Write-Ok "$($out.Count) 件の IPv6 近隣を検出"
    return ,$out
}

# ==========================================
# 5. WiFi情報（該当する場合）
# ==========================================

function Get-WifiInfo {
    Write-Step "WiFi接続情報を確認中..."

    try {
        $output = netsh wlan show interfaces 2>$null
        if (-not $output -or $LASTEXITCODE -ne 0) {
            return $null
        }

        $info = [ordered]@{
            ssid     = ""
            bssid    = ""
            signal   = ""
            band     = ""
            channel  = ""
            radio    = ""
            authentication = ""
        }

        # netsh のラベルは OS 言語で変わるため、英語/日本語の両方に対応する
        foreach ($line in $output) {
            if ($line -match '^\s*SSID\s*:\s*(.+)$' -and -not $info.ssid)         { $info.ssid = $Matches[1].Trim() }
            if ($line -match '^\s*BSSID\s*:\s*(.+)$')                              { $info.bssid = $Matches[1].Trim() }
            if ($line -match '^\s*(?:Signal|シグナル)\s*:\s*(.+)$')                { $info.signal = $Matches[1].Trim() }
            if ($line -match '^\s*(?:Band|バンド|帯域)\s*:\s*(.+)$')               { $info.band = $Matches[1].Trim() }
            if ($line -match '^\s*(?:Channel|チャネル)\s*:\s*(.+)$')               { $info.channel = $Matches[1].Trim() }
            if ($line -match '^\s*(?:Radio type|無線の種類)\s*:\s*(.+)$')          { $info.radio = $Matches[1].Trim() }
            if ($line -match '^\s*(?:Authentication|認証)\s*:\s*(.+)$')            { $info.authentication = $Matches[1].Trim() }
        }

        if ($info.ssid) { return $info }
        return $null
    } catch {
        Write-Warn2 "WiFi情報取得失敗: $_"
        return $null
    }
}

# ==========================================
# 6. サブネットスキャン（オプション）
# ==========================================

function Invoke-PingSweepAsync {
    <#
        PowerShell 5.1 でも動く並列 ping。

        5.1 には ForEach-Object -Parallel が無いため、これまで -Full /
        -ScanSubnet は PS7 必須だった。SendPingAsync を一度にまとめて発行し
        Task をまとめて待てば、Runspace を立てずに同じことができる。
    #>
    param([string[]]$Targets, [int]$TimeoutMs, [int]$BatchSize = 50)

    $found = @()
    $all = @($Targets)
    if ($all.Count -eq 0) { return $found }
    if ($BatchSize -lt 1) { $BatchSize = 1 }

    for ($i = 0; $i -lt $all.Count; $i += $BatchSize) {
        $end = [math]::Min($i + $BatchSize - 1, $all.Count - 1)
        $chunk = $all[$i..$end]

        $pings = @()
        $tasks = @()
        foreach ($ip in $chunk) {
            $p = New-Object System.Net.NetworkInformation.Ping
            $pings += $p
            try {
                $tasks += [PSCustomObject]@{ ip = $ip; task = $p.SendPingAsync($ip, $TimeoutMs) }
            } catch {
                $tasks += [PSCustomObject]@{ ip = $ip; task = $null }
            }
        }

        foreach ($t in $tasks) {
            if (-not $t.task) { continue }
            try {
                # タイムアウトは Ping 側が面倒を見るが、念のため上限を置く
                if ($t.task.Wait($TimeoutMs + 1000)) {
                    $reply = $t.task.Result
                    if ($reply -and $reply.Status -eq 'Success') {
                        $found += [pscustomobject]@{
                            ipAddress    = $t.ip
                            responseTime = $reply.RoundtripTime
                        }
                    }
                }
            } catch { }
        }
        foreach ($p in $pings) { try { $p.Dispose() } catch { } }
    }
    return $found
}

function Invoke-SubnetScan {
    param(
        [array]$Adapters,
        [int]$Timeout,
        [int]$Throttle
    )

    Write-Step "サブネットスキャンを実施中（時間がかかります）..."
    $discovered = @()

    foreach ($adapter in $Adapters) {
        foreach ($ipInfo in $adapter.ipv4Addresses) {
            if (-not (Test-PrivateIpv4Address -IpAddress $ipInfo.address)) {
                Write-Warn2 "  $($ipInfo.address)/$($ipInfo.prefixLength) はスキャン対象外（RFC1918 のプライベート IPv4 ではありません）"
                continue
            }
            if ($ipInfo.prefixLength -lt 22 -or $ipInfo.prefixLength -gt 30) {
                Write-Warn2 "  $($ipInfo.address)/$($ipInfo.prefixLength) はスキャン対象外（/22～/30 が対象）"
                continue
            }

            $subnet = Get-SubnetRange -IpAddress $ipInfo.address -PrefixLength $ipInfo.prefixLength
            Write-Host "  -> スキャン中: $($subnet.network)/$($ipInfo.prefixLength) ($($subnet.hosts.Count)ホスト)" -ForegroundColor Gray

            $localIp = $ipInfo.address
            $targets = @($subnet.hosts | Where-Object { $_ -ne $localIp })

            if ($PSVersionTable.PSVersion.Major -ge 7) {
                $results = $targets | ForEach-Object -ThrottleLimit $Throttle -Parallel {
                    $ip = $_
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    try {
                        $reply = $ping.Send($ip, $using:Timeout)
                        if ($reply.Status -eq 'Success') {
                            [pscustomobject]@{
                                ipAddress    = $ip
                                responseTime = $reply.RoundtripTime
                            }
                        }
                    } catch { } finally { $ping.Dispose() }
                }
            } else {
                # PowerShell 5.1 には ForEach-Object -Parallel が無い。
                # SendPingAsync を並べて待つ方式なら 5.1 でも同じ速さで走る
                # （Runspace を立てるより軽い）。
                $results = Invoke-PingSweepAsync -Targets $targets -TimeoutMs $Timeout -BatchSize $Throttle
            }

            $discovered += @($results)
        }
    }

    Write-Ok "$($discovered.Count)個のホストを発見"
    return @($discovered)
}

function Get-SubnetRange {
    param([string]$IpAddress, [int]$PrefixLength)

    $ip = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    $mask = [byte[]]::new(4)
    $bits = $PrefixLength
    for ($i = 0; $i -lt 4; $i++) {
        if ($bits -ge 8)        { $mask[$i] = 0xFF; $bits -= 8 }
        elseif ($bits -gt 0)    { $mask[$i] = (0xFF -shl (8 - $bits)) -band 0xFF; $bits = 0 }
        else                    { $mask[$i] = 0x00 }
    }

    $network = [byte[]]::new(4)
    $broadcast = [byte[]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
        $network[$i]   = $ip[$i] -band $mask[$i]
        $broadcast[$i] = $network[$i] -bor (0xFF -bxor $mask[$i])
    }

    $netInt = [BitConverter]::ToUInt32([byte[]]@($network[3], $network[2], $network[1], $network[0]), 0)
    $bcInt  = [BitConverter]::ToUInt32([byte[]]@($broadcast[3], $broadcast[2], $broadcast[1], $broadcast[0]), 0)

    $hosts = @()
    for ($n = $netInt + 1; $n -lt $bcInt; $n++) {
        $bytes = [BitConverter]::GetBytes($n)
        $hosts += "$($bytes[3]).$($bytes[2]).$($bytes[1]).$($bytes[0])"
    }

    return @{
        network = ($network -join '.')
        hosts   = $hosts
    }
}

# ==========================================
# 7. 逆引きDNS解決
# ==========================================

function Resolve-HostsByDns {
    param([array]$Ips)

    Write-Step "$($Ips.Count)件の逆引きDNSを解決中..."
    $result = @{}

    foreach ($ip in $Ips) {
        try {
            $r = Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop
            $hostname = ($r | Where-Object Type -eq 'PTR' | Select-Object -First 1).NameHost
            if ($hostname) {
                $result[$ip] = $hostname.TrimEnd('.')
            }
        } catch { }
    }

    Write-Ok "$($result.Count)件のホスト名を解決"
    return $result
}

# ==========================================
# 8. Traceroute（オプション）
# ==========================================

function Invoke-TraceRoute {
    param([string]$Target, [int]$MaxHops = 15)

    Write-Step "$Target へのtracerouteを実施中..."
    $hops = @()

    try {
        $output = & tracert -d -h $MaxHops -w 1000 $Target 2>$null
        $hopNum = 0
        foreach ($line in $output) {
            # 例: "  1     1 ms     1 ms     1 ms  192.168.1.1"
            #     "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"  (1ms未満。宅内GWで頻出)
            if ($line -match '^\s*(\d+)\s+(?:<?\s*(\d+)\s*ms|\*)\s+(?:<?\s*(\d+)\s*ms|\*)\s+(?:<?\s*(\d+)\s*ms|\*)\s+(.+)$') {
                $hopNum = [int]$Matches[1]
                $rtts = @($Matches[2], $Matches[3], $Matches[4]) | Where-Object { $_ } | ForEach-Object { [int]$_ }
                $ipPart = $Matches[5].Trim()
                if ($ipPart -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    $hops += [ordered]@{
                        hop        = $hopNum
                        ipAddress  = $Matches[1]
                        avgRtt     = if ($rtts.Count -gt 0) { ($rtts | Measure-Object -Average).Average } else { $null }
                    }
                }
            }
        }
    } catch {
        Write-Warn2 "Traceroute失敗: $_"
    }

    Write-Ok "$($hops.Count)ホップを記録"
    return @{ target = $Target; hops = $hops }
}

# ==========================================
# 9. アクティブな通信（このPCのTCP接続）
# ==========================================

function Test-PrivateIpAddr {
    param([string]$Ip)
    if (-not $Ip) { return $false }
    if ($Ip -like '10.*' -or $Ip -like '192.168.*' -or $Ip -like '169.254.*') { return $true }
    if ($Ip -match '^172\.(\d+)\.') { $o = [int]$Matches[1]; if ($o -ge 16 -and $o -le 31) { return $true } }
    if ($Ip -match '^100\.(\d+)\.') { $o = [int]$Matches[1]; if ($o -ge 64 -and $o -le 127) { return $true } }
    return $false
}

function Get-ActiveConnections {
    Write-Step "アクティブな通信(TCP接続)を収集中..."

    try {
        $conns = @(Get-NetTCPConnection -State Established -ErrorAction Stop)
    } catch {
        Write-Warn2 "TCP接続情報を取得できませんでした: $($_.Exception.Message)"
        return ,@()
    }

    $procCache = @{}
    $agg = @{}   # key: process|remote|port -> record

    foreach ($c in $conns) {
        $ra = [string]$c.RemoteAddress
        if (-not $ra) { continue }
        if ($ra -in @('127.0.0.1', '::1', '0.0.0.0', '::')) { continue }
        if ($ra -like '127.*' -or $ra -like 'fe80*' -or $ra -like '169.254.*' -or $ra -like '::ffff:127*') { continue }

        $procId = [int]$c.OwningProcess
        if (-not $procCache.ContainsKey($procId)) {
            $pn = $null
            try { $pn = (Get-Process -Id $procId -ErrorAction Stop).ProcessName } catch { $pn = "pid:$procId" }
            $procCache[$procId] = $pn
        }
        $proc = $procCache[$procId]
        $port = [int]$c.RemotePort
        $key = "$proc|$ra|$port"

        if ($agg.ContainsKey($key)) {
            $agg[$key].count++
        } else {
            $scope = if (Test-PrivateIpAddr $ra) { 'LAN' } else { 'Internet' }
            $agg[$key] = [pscustomobject]@{
                process       = $proc
                remoteAddress = $ra
                remotePort    = $port
                scope         = $scope
                count         = 1
            }
        }
    }

    $result = @($agg.Values | Sort-Object count -Descending | Select-Object -First 60)
    Write-Ok "$($result.Count) 件のアクティブ接続を集計（プロセス x 宛先 x ポート）"
    return ,$result
}

function Get-BandwidthUsage {
    <#
        「今どれだけ流れているか」と「どのアプリが食っていそうか」を測る。

        注意: Windows にはプロセス別の "ネットワーク" バイト数のカウンタが無い
        （タスクマネージャは ETW を使っており、管理者権限が要る）。
        そこで次のように分けている:
          - アダプタ単位の実測: Get-NetAdapterStatistics の差分。これは正確。
          - プロセス別: I/O バイト数（ディスクも含む）を、外部と通信中の
            プロセスに限って並べた推定値。断定はせず候補として出す。
    #>
    param([int]$Seconds = 3)
    Write-Step "帯域の使用状況を測定中（${Seconds}秒）..."

    # --- アダプタ単位（正確） ---
    $before = @{}
    try {
        foreach ($s in @(Get-NetAdapterStatistics -ErrorAction Stop)) {
            $before[$s.Name] = @{ rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes }
        }
    } catch {
        Write-Warn2 "アダプタ統計を取得できませんでした: $($_.Exception.Message)"
        return $null
    }

    # --- プロセス別（推定）: 待ち時間を使って I/O レートを採る ---
    $procRates = @{}
    try {
        $samples = Get-Counter -Counter '\Process(*)\IO Data Bytes/sec' -SampleInterval 1 -MaxSamples $Seconds -ErrorAction Stop
        $agg = @{}
        foreach ($set in @($samples)) {
            foreach ($c in @($set.CounterSamples)) {
                $inst = [string]$c.InstanceName
                if ($inst -in @('_total', 'idle', 'memory compression')) { continue }
                if (-not $agg.ContainsKey($inst)) { $agg[$inst] = @() }
                $agg[$inst] += [double]$c.CookedValue
            }
        }
        foreach ($k in $agg.Keys) {
            $procRates[$k] = ($agg[$k] | Measure-Object -Average).Average
        }
    } catch {
        Start-Sleep -Seconds $Seconds
    }

    $after = @{}
    try {
        foreach ($s in @(Get-NetAdapterStatistics -ErrorAction Stop)) {
            $after[$s.Name] = @{ rx = [int64]$s.ReceivedBytes; tx = [int64]$s.SentBytes }
        }
    } catch { return $null }

    $adapters = @()
    foreach ($name in $after.Keys) {
        if (-not $before.ContainsKey($name)) { continue }
        $dRx = $after[$name].rx - $before[$name].rx
        $dTx = $after[$name].tx - $before[$name].tx
        if ($dRx -lt 0 -or $dTx -lt 0) { continue }   # カウンタ巻き戻し
        $adapters += [ordered]@{
            name         = $name
            downloadMbps = [math]::Round(($dRx * 8) / ($Seconds * 1e6), 2)
            uploadMbps   = [math]::Round(($dTx * 8) / ($Seconds * 1e6), 2)
            receivedMB   = [math]::Round($dRx / 1MB, 2)
            sentMB       = [math]::Round($dTx / 1MB, 2)
        }
    }

    # --- 外部と通信中のプロセスに絞る ---
    $netPids = @{}
    try {
        foreach ($c in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
            $ra = [string]$c.RemoteAddress
            if (-not $ra) { continue }
            # 宅内・ループバックは帯域の話では除く
            if ($ra -match '^(127\.|10\.|192\.168\.|169\.254\.|::1|fe80:)') { continue }
            if ($ra -match '^172\.(1[6-9]|2[0-9]|3[01])\.') { continue }
            if ($c.OwningProcess) { $netPids[[int]$c.OwningProcess] = $true }
        }
    } catch { }

    # インスタンス名 → PID。Windows 11 は "name_pid" 形式のことがあるが、
    # 環境によって "name#1" になるため ID Process カウンタで確実に引く
    $instToPid = @{}
    try {
        foreach ($c in @((Get-Counter -Counter '\Process(*)\ID Process' -ErrorAction Stop).CounterSamples)) {
            $instToPid[[string]$c.InstanceName] = [int]$c.CookedValue
        }
    } catch { }

    $procs = @()
    foreach ($inst in $procRates.Keys) {
        $rate = $procRates[$inst]
        if ($rate -lt 50KB) { continue }   # 小さすぎるものは並べない
        $procPid = if ($instToPid.ContainsKey($inst)) { $instToPid[$inst] }
                   elseif ($inst -match '^(.+)_(\d+)$') { [int]$Matches[2] }
                   else { $null }
        if (-not $procPid -or -not $netPids.ContainsKey($procPid)) { continue }

        $pname = $inst
        try { $pname = (Get-Process -Id $procPid -ErrorAction Stop).ProcessName } catch { }
        $procs += [ordered]@{
            processName = $pname
            processId   = $procPid
            ioMbps      = [math]::Round(($rate * 8) / 1e6, 2)
        }
    }
    $procs = @($procs | Sort-Object { -$_.ioMbps } | Select-Object -First 10)

    # Measure-Object は hashtable のキーをプロパティとして読めないので自前で合計する
    $totalDown = 0.0; $totalUp = 0.0
    foreach ($a in $adapters) { $totalDown += [double]$a.downloadMbps; $totalUp += [double]$a.uploadMbps }
    Write-Ok ("現在の通信量: 下り {0:N2} Mbps / 上り {1:N2} Mbps（外部と通信中のプロセス {2} 件）" -f `
              $totalDown, $totalUp, $procs.Count)

    return [ordered]@{
        sampledSeconds = $Seconds
        adapters       = @($adapters)
        processes      = @($procs)
        note           = 'プロセス別の値はディスクI/Oを含む推定です（Windowsにプロセス別ネットワークカウンタが無いため）。外部と通信中のプロセスのみ表示しています。'
    }
}

# ==========================================
# メイン処理
# ==========================================

Write-Host "=========================================" -ForegroundColor Magenta
Write-Host " Network Topology Mapper - Collector" -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta

$data = [ordered]@{
    metadata        = Get-HostMetadata
    adapters        = Get-AdapterInfo
    routes          = Get-RouteInfo
    neighbors       = Get-NeighborInfo
    neighbors6      = Get-Neighbor6Info
    wifi            = Get-WifiInfo
    discoveredHosts = @()
    hostnames       = @{}
    traceroute      = $null
    activeConnections = Get-ActiveConnections
    bandwidth         = if ($SkipBandwidth) { $null } else { Get-BandwidthUsage -Seconds $BandwidthSeconds }
}

if ($ScanSubnet) {
    if (-not $ScanInterfaceIndex -or @($ScanInterfaceIndex).Count -eq 0) {
        throw '-ScanSubnet には -ScanInterfaceIndex が必要です。対象を確認してから明示してください。'
    }
    $approvedIndexes = @($ScanInterfaceIndex | Sort-Object -Unique)
    $scanAdapters = @($data.adapters | Where-Object { $approvedIndexes -contains [int]$_.interfaceIndex })
    if ($scanAdapters.Count -eq 0) {
        throw '指定されたインターフェイスに、スキャン可能なアクティブ IPv4 アドレスがありません。'
    }
    $unknownIndexes = @($approvedIndexes | Where-Object { $scanAdapters.interfaceIndex -notcontains $_ })
    if ($unknownIndexes.Count -gt 0) {
        throw "指定されたインターフェイスはアクティブではありません: $($unknownIndexes -join ', ')"
    }
    $data.discoveredHosts = Invoke-SubnetScan -Adapters $scanAdapters -Timeout $ScanTimeout -Throttle $ScanThrottle

    $allowedCidrs = @()
    foreach ($adapter in $scanAdapters) {
        foreach ($ipInfo in @($adapter.ipv4Addresses)) {
            if ([int]$ipInfo.prefixLength -ge 22 -and [int]$ipInfo.prefixLength -le 30 -and
                (Test-PrivateIpv4Address -IpAddress $ipInfo.address)) {
                $subnet = Get-SubnetRange -IpAddress $ipInfo.address -PrefixLength ([int]$ipInfo.prefixLength)
                $allowedCidrs += "$($subnet.network)/$($ipInfo.prefixLength)"
            }
        }
    }
    if ($allowedCidrs.Count -eq 0) {
        throw '選択されたインターフェイスに安全な調査範囲（RFC1918 /22～/30）がありません。'
    }
    $data['scanScope'] = [ordered]@{
        interfaceIndexes = @($approvedIndexes)
        allowedCidrs     = @($allowedCidrs | Sort-Object -Unique)
    }
}

if ($ResolveHostnames) {
    $allIps = @()
    if ($ScanSubnet) {
        $allIps += @($data.neighbors | Where-Object { $approvedIndexes -contains [int]$_.interfaceIndex } | ForEach-Object { $_.ipAddress })
    }
    $allIps += @($data.discoveredHosts | ForEach-Object { $_.ipAddress })
    $allIps = $allIps | Sort-Object -Unique

    if ($allIps.Count -gt 0) {
        $data.hostnames = Resolve-HostsByDns -Ips $allIps
    }
}

if ($IncludeTraceroute) {
    $data.traceroute = Invoke-TraceRoute -Target $TracerouteTarget
}

# 出力ディレクトリ作成
$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$data | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Ok "収集完了: $OutputPath"
Write-Host ""
