<#
.SYNOPSIS
    LAN内機器を特定する: MAC OUI、NetBIOS、SSDP/UPnP、HTTPバナーで
    network-data.json を拡充する。

.DESCRIPTION
    Collect-NetworkInfo.ps1 が出力した JSON を読み込み、以下のプローブを実施:
      1. IEEE OUI データベースで MAC アドレスからベンダーを引く
      2. nbtstat で Windows ホストの NetBIOS 名・ワークグループを取得
      3. SSDP M-SEARCH で UPnP デバイス（ルーター、TV、ゲーム機、NAS等）を発見
      4. mDNS/DNS-SD で Bonjour 機器（iPhone、Mac、Chromecast、プリンタ等）を発見
      5. HTTP (80/443) でゲートウェイと UPnP デバイスのバナーを取得

    結果は元の JSON に deviceFingerprints / ssdpDevices として追記される。

.PARAMETER InputPath
    入力 JSON（デフォルト: ..\output\network-data.json）

.PARAMETER OutputPath
    出力先（同じパスを指定すると上書き）

.PARAMETER SkipSsdp
    SSDP ディスカバリをスキップ

.PARAMETER SkipNetbios
    NetBIOS 解決をスキップ

.PARAMETER SkipHttp
    HTTP プローブをスキップ

.PARAMETER SkipOui
    OUI ルックアップをスキップ

.PARAMETER SkipMdns
    mDNS/Bonjour プローブをスキップ

.PARAMETER NoExternalDownloads
    IEEE OUI データを外部取得せず、既存キャッシュまたは組み込み DB だけを使う
#>

[CmdletBinding()]
param(
    [string]$InputPath = "$PSScriptRoot\..\output\network-data.json",
    [string]$OutputPath = "$PSScriptRoot\..\output\network-data.json",
    # 能動プローブを許可する IPv4 CIDR。省略時は収集 JSON の scanScope を使用する。
    [string[]]$AllowedCidrs,
    [switch]$SkipSsdp,
    [switch]$SkipNetbios,
    [switch]$SkipHttp,
    [switch]$SkipOui,
    [switch]$SkipMdns,
    [switch]$SkipIgd,
    # 外部から OUI データを取得しない。既存キャッシュまたは組み込みDBだけを使う
    [switch]$NoExternalDownloads,
    # 代表ポートの確認（自宅ネットワーク向け。組織のネットワークでは実行可否を確認すること）
    [switch]$SkipPortScan,
    [int]$PortScanTimeoutMs = 400,
    [int]$SsdpTimeoutSec = 5,
    [int]$MdnsTimeoutSec = 4,
    [int]$HttpTimeoutSec = 3,
    # 軽量モード: 直列で遅い NetBIOS / HTTP プローブをスキップし OUI + SSDP のみ実施（最速）
    [switch]$Light,
    # 並列実行数（PowerShell 7 以上でのみ有効）
    [int]$ThrottleLimit = 32
)

$ErrorActionPreference = "Continue"

# 軽量モード: 直列で時間のかかる NetBIOS/HTTP をスキップ（OUI + SSDP のみ）
if ($Light) {
    $SkipNetbios  = $true
    $SkipHttp     = $true
    $SkipPortScan = $true
}

# 並列実行可否（ForEach-Object -Parallel は PowerShell 7 以上）
$CanParallel = $PSVersionTable.PSVersion.Major -ge 7

function Write-Step  { param([string]$M) Write-Host "[*] $M" -ForegroundColor Cyan }
function Write-Ok    { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn2 { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }

function Test-Ipv4InCidr {
    param([string]$IpAddress, [string]$Cidr)

    try {
        $parts = $Cidr -split '/', 2
        if ($parts.Count -ne 2) { return $false }
        $prefix = 0
        if (-not [int]::TryParse($parts[1], [ref]$prefix) -or $prefix -lt 0 -or $prefix -gt 32) { return $false }
        $ip = [Net.IPAddress]::Parse($IpAddress)
        $network = [Net.IPAddress]::Parse($parts[0])
        if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            $network.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
        $ipBytes = $ip.GetAddressBytes()
        $networkBytes = $network.GetAddressBytes()
        $fullBytes = [math]::Floor($prefix / 8)
        $remainingBits = $prefix % 8
        for ($i = 0; $i -lt $fullBytes; $i++) {
            if ($ipBytes[$i] -ne $networkBytes[$i]) { return $false }
        }
        if ($remainingBits -gt 0) {
            $mask = [byte](256 - [math]::Pow(2, (8 - $remainingBits)))
            if (($ipBytes[$fullBytes] -band $mask) -ne ($networkBytes[$fullBytes] -band $mask)) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-IpInAllowedCidrs {
    param([string]$IpAddress, [string[]]$Cidrs)
    foreach ($cidr in @($Cidrs)) {
        if (Test-Ipv4InCidr -IpAddress $IpAddress -Cidr $cidr) { return $true }
    }
    return $false
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
# JSON ヘルパー (PS5.1 互換)
# ==========================================
function ConvertTo-HashtableRecursive {
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [PSCustomObject]) {
        $h = [ordered]@{}
        foreach ($p in $Obj.PSObject.Properties) {
            $h[$p.Name] = ConvertTo-HashtableRecursive $p.Value
        }
        return $h
    }
    if ($Obj -is [System.Collections.IList] -and $Obj -isnot [string]) {
        return @($Obj | ForEach-Object { ConvertTo-HashtableRecursive $_ })
    }
    return $Obj
}

# ==========================================
# 信頼できない LAN 応答を安全に読むための HTTP / XML ヘルパー
# ==========================================
function Test-SafeLocalHttpUri {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$ExpectedIp
    )

    try {
        $parsed = [Uri]$Uri
        if (-not $parsed.IsAbsoluteUri -or $parsed.Scheme -notin @('http', 'https')) { return $false }
        if ($parsed.UserInfo -or $parsed.Fragment) { return $false }

        $actualAddress = $null
        $expectedAddress = $null
        $hostAddress = $parsed.Host.Trim('[', ']')
        if (-not [System.Net.IPAddress]::TryParse($hostAddress, [ref]$actualAddress)) { return $false }
        if (-not [System.Net.IPAddress]::TryParse($ExpectedIp, [ref]$expectedAddress)) { return $false }
        return $actualAddress.Equals($expectedAddress)
    } catch {
        return $false
    }
}

function Read-LimitedResponseText {
    param(
        [Parameter(Mandatory)]$Response,
        [ValidateRange(1024, 4194304)][int]$MaxChars = 1048576
    )

    if ($Response.ContentLength -gt ($MaxChars * 4L)) {
        throw "HTTP 応答が上限を超えています ($($Response.ContentLength) bytes)"
    }

    $stream = $null
    $reader = $null
    try {
        $stream = $Response.GetResponseStream()
        if (-not $stream) { return '' }
        $reader = New-Object System.IO.StreamReader($stream)
        $buffer = New-Object char[] 8192
        $text = New-Object System.Text.StringBuilder
        while (($read = $reader.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if (($text.Length + $read) -gt $MaxChars) { throw "HTTP 応答が上限を超えています ($MaxChars 文字)" }
            [void]$text.Append($buffer, 0, $read)
        }
        return $text.ToString()
    } finally {
        if ($reader) { $reader.Dispose() }
        elseif ($stream) { $stream.Dispose() }
    }
}

function Invoke-SafeLocalHttpRequest {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$ExpectedIp,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string]$Body,
        [hashtable]$Headers = @{},
        [string]$ContentType,
        [ValidateRange(1, 30)][int]$TimeoutSec = 4,
        [ValidateRange(1024, 4194304)][int]$MaxResponseChars = 1048576,
        [switch]$AllowErrorResponse
    )

    if (-not (Test-SafeLocalHttpUri -Uri $Uri -ExpectedIp $ExpectedIp)) {
        throw "LAN 応答の接続先が応答元 IP と一致しません: $Uri (応答元: $ExpectedIp)"
    }

    $request = [System.Net.HttpWebRequest]::Create($Uri)
    $request.Method = $Method
    $request.AllowAutoRedirect = $false
    $request.Timeout = $TimeoutSec * 1000
    $request.ReadWriteTimeout = $TimeoutSec * 1000
    $request.MaximumResponseHeadersLength = 32
    $request.UserAgent = 'NetworkTopologyMapper/1.0'
    $request.KeepAlive = $false
    if ($ContentType) { $request.ContentType = $ContentType }
    foreach ($name in $Headers.Keys) { $request.Headers.Add([string]$name, [string]$Headers[$name]) }

    if ($Method -eq 'POST') {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body)
        if ($bytes.Length -gt 65536) { throw 'HTTP 要求本文が上限を超えています' }
        $request.ContentLength = $bytes.Length
        $requestStream = $request.GetRequestStream()
        try { $requestStream.Write($bytes, 0, $bytes.Length) } finally { $requestStream.Dispose() }
    }

    $response = $null
    try {
        try {
            $response = $request.GetResponse()
        } catch {
            $webException = $_.Exception
            while ($webException -and -not ($webException -is [System.Net.WebException])) {
                $webException = $webException.InnerException
            }
            if ($AllowErrorResponse -and $webException -and $webException.Response) {
                $response = $webException.Response
            } else {
                throw
            }
        }

        $content = Read-LimitedResponseText -Response $response -MaxChars $MaxResponseChars
        return [PSCustomObject]@{
            statusCode = if ($response.StatusCode) { [int]$response.StatusCode } else { $null }
            headers    = $response.Headers
            content    = $content
        }
    } finally {
        if ($response) { try { $response.Close() } catch { } }
    }
}

function ConvertFrom-SafeXml {
    param(
        [Parameter(Mandatory)][string]$Text,
        [ValidateRange(1024, 4194304)][int]$MaxChars = 1048576
    )

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = $MaxChars
    $stringReader = New-Object System.IO.StringReader($Text)
    $xmlReader = $null
    try {
        $xmlReader = [System.Xml.XmlReader]::Create($stringReader, $settings)
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($xmlReader)
        return $document
    } finally {
        if ($xmlReader) { $xmlReader.Dispose() }
        $stringReader.Dispose()
    }
}

# ==========================================
# 1. OUI Database
# ==========================================
$script:OuiCacheDir   = Join-Path $env:LOCALAPPDATA "NetworkTopologyMapper"
$script:OuiCacheFile  = Join-Path $script:OuiCacheDir "oui-cache.json"
$script:OuiUrl        = "https://standards-oui.ieee.org/oui/oui.csv"
$script:OuiMaxAgeDays = 90

function Get-OuiMiniDatabase {
    # フォールバック用ミニDB (主要ベンダーのみ)
    return @{
        "0024A5"="BUFFALO INC.";    "00901A"="BUFFALO INC.";    "4CE676"="BUFFALO INC.";
        "B01041"="BUFFALO INC.";    "A0B3CC"="BUFFALO INC.";    "001D73"="BUFFALO INC.";
        "6C71D9"="BUFFALO INC.";    "8C10D4"="BUFFALO INC.";    "DCFB02"="BUFFALO INC.";
        "001B63"="Apple";           "002608"="Apple";           "286ABA"="Apple";
        "3C0754"="Apple";           "A45E60"="Apple";           "ACDE48"="Apple";
        "001632"="Samsung";         "5C0A5B"="Samsung";         "001E3D"="Samsung";
        "0009BF"="Nintendo";        "0017AB"="Nintendo";        "7CBB8A"="Nintendo";
        "9CE635"="Nintendo";        "98B6E9"="Nintendo";       "ECC40D"="Nintendo";
        "A4C1E8"="Nintendo";
        "00014A"="Sony";            "0013A9"="Sony";            "0024BE"="Sony";
        "BC60A7"="Sony";            "FCF152"="Sony Interactive";
        "001DD8"="Microsoft";       "7C1E52"="Microsoft";       "501AC5"="Microsoft";
        "F4F5D8"="Google";          "F4F5DB"="Google";          "001A11"="Google";
        "F4F5E8"="TP-Link";         "B0BE76"="TP-Link";         "C46E1F"="TP-Link";
        "60E327"="Espressif (IoT)"; "08D1F9"="Espressif (IoT)"; "BCDDC2"="Espressif (IoT)";
        "240AC4"="Espressif (IoT)"; "A4CF12"="Espressif (IoT)";
        "001517"="Intel";           "AC1F6B"="Intel";           "A0A8CD"="Intel";
        "00904C"="Broadcom";        "B827EB"="Raspberry Pi";    "DCA632"="Raspberry Pi";
        "2CCF67"="Raspberry Pi";    "D83ADD"="Raspberry Pi";
        "5CF370"="ASUSTek";         "ACBC32"="ASUSTek";         "1C872C"="ASUSTek";
        "00408C"="Axis Comm.";      "001D7E"="NEC Platforms";   "0080C8"="NEC Platforms";
        "BC5C4C"="ELECOM";          "3897A4"="ELECOM";          "04AB18"="ELECOM";
        "3476C5"="I-O DATA";        "00A0B0"="I-O DATA";        "5041B9"="I-O DATA";
        "20FE00"="Amazon";          "E84C4A"="Amazon";          "C86C3D"="Amazon";
        "2884FA"="Sharp";           "9CC7D1"="Sharp";           "34F62D"="Sharp";
        "8CC121"="Panasonic";       "A81374"="Panasonic";       "04209A"="Panasonic";
        "00A0DE"="Yamaha";          "F4D580"="Yamaha";          "AC44F2"="Yamaha";
        "F48B32"="Xiaomi";          "60AB67"="Xiaomi";          "E01F88"="Xiaomi"
    }
}

function Get-OuiDatabase {
    param([switch]$CacheOnly)

    if (Test-Path $script:OuiCacheFile) {
        $age = (Get-Date) - (Get-Item $script:OuiCacheFile).LastWriteTime
        if ($age.TotalDays -lt $script:OuiMaxAgeDays -or $CacheOnly) {
            try {
                $obj = Get-Content $script:OuiCacheFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $h = @{}
                foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
                Write-Ok "OUI DB: キャッシュロード ($($h.Count) entries)"
                return $h
            } catch {
                Write-Warn2 "OUIキャッシュを読み込めませんでした"
            }
        }
    }

    if ($CacheOnly) {
        Write-Warn2 "外部取得を無効にしているため、組み込み OUI DB を使います"
        return Get-OuiMiniDatabase
    }

    Write-Step "OUI データベースをダウンロード中（初回のみ、約5MB）..."
    if (-not (Test-Path $script:OuiCacheDir)) {
        New-Item -ItemType Directory -Path $script:OuiCacheDir -Force | Out-Null
    }

    # IEEE の公開リストだけを利用する。第三者が加工したデータは取り込まない。
    $sources = @(
        @{ Url = "https://standards-oui.ieee.org/oui/oui.csv"; Format = "csv" }
        @{ Url = "https://standards-oui.ieee.org/oui/oui.txt"; Format = "txt" }
    )
    $headers = @{
        "User-Agent" = "NetworkTopologyMapper/1.0"
        "Accept"     = "text/csv,text/plain,*/*"
    }

    $oldProg = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    foreach ($src in $sources) {
        try {
            Write-Host "  -> $($src.Url) ..." -ForegroundColor Gray
            $resp = Invoke-WebRequest -Uri $src.Url -Headers $headers -UseBasicParsing -TimeoutSec 30
            $h = @{}
            if ($src.Format -eq 'csv') {
                foreach ($line in ($resp.Content -split "`n")) {
                    if ($line -match '^(MA-L|MA-M|MA-S),([0-9A-Fa-f]{6,9}),"([^"]+)"') {
                        $h[$Matches[2].ToUpper()] = $Matches[3]
                    }
                }
            } elseif ($src.Format -eq 'txt') {
                # IEEE oui.txt: "00-00-00   (hex)\t\tXEROX CORPORATION"
                foreach ($line in ($resp.Content -split "`n")) {
                    if ($line -match '^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$') {
                        $h[($Matches[1] -replace '-','').ToUpper()] = $Matches[2].Trim()
                    }
                }
            }
            if ($h.Count -gt 100) {
                ($h | ConvertTo-Json -Compress) | Set-Content $script:OuiCacheFile -Encoding UTF8
                Write-Ok "OUI DB: ダウンロード完了 ($($h.Count) entries)"
                $ProgressPreference = $oldProg
                return $h
            }
        } catch {
            Write-Warn2 "  失敗: $($_.Exception.Message.Split([Environment]::NewLine)[0])"
        }
    }
    $ProgressPreference = $oldProg

    Write-Warn2 "全ソースから取得失敗、組み込みミニDBにフォールバック"
    return Get-OuiMiniDatabase
}

function Get-OuiVendor {
    param([string]$Mac, [hashtable]$Db)
    if (-not $Mac -or -not $Db) { return $null }
    $clean = ($Mac -replace '[:\-]', '').ToUpper()
    if ($clean.Length -lt 6) { return $null }
    return $Db[$clean.Substring(0, 6)]
}

# ==========================================
# 2. SSDP / UPnP Discovery
# ==========================================
function Invoke-SsdpDiscovery {
    param(
        [int]$TimeoutSec = 5,
        [string[]]$LocalIPs = @()
    )
    Write-Step "SSDP/UPnP デバイスを探索中（${TimeoutSec}秒）..."

    if ($LocalIPs.Count -eq 0) {
        # 引数なしの場合は IPAddress.Any にバインド（後方互換）
        $bindList = @([System.Net.IPAddress]::Any)
    } else {
        $bindList = @()
        foreach ($ip in $LocalIPs) {
            try { $bindList += [System.Net.IPAddress]::Parse($ip) } catch { }
        }
        if ($bindList.Count -eq 0) { $bindList = @([System.Net.IPAddress]::Any) }
    }

    $multicastEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('239.255.255.250'), 1900)
    $multicastAddr = [System.Net.IPAddress]::Parse('239.255.255.250')
    $msearch = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 3`r`nST: ssdp:all`r`n`r`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($msearch)

    $allResponses = @()
    $seen = @{}

    foreach ($localAddr in $bindList) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.UdpClient
            $client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,
                                           [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
            # 該当アダプタの IP にバインド（マルチキャストの送信元 NIC を確定）
            $localEp = New-Object System.Net.IPEndPoint($localAddr, 0)
            $client.Client.Bind($localEp)

            # マルチキャストグループに参加（特定 NIC 上）
            try {
                if ($localAddr -ne [System.Net.IPAddress]::Any) {
                    $client.JoinMulticastGroup($multicastAddr, $localAddr)
                } else {
                    $client.JoinMulticastGroup($multicastAddr)
                }
            } catch { }

            $client.Client.ReceiveTimeout = 1000
            Write-Host "  -> $localAddr から M-SEARCH 送信" -ForegroundColor Gray

            # 信頼性のため2回送信
            $client.Send($bytes, $bytes.Length, $multicastEp) | Out-Null
            Start-Sleep -Milliseconds 500
            $client.Send($bytes, $bytes.Length, $multicastEp) | Out-Null

            $end = (Get-Date).AddSeconds($TimeoutSec)
            while ((Get-Date) -lt $end) {
                try {
                    $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $data = $client.Receive([ref]$remoteEp)
                    $text = [System.Text.Encoding]::UTF8.GetString($data)
                    $ip = $remoteEp.Address.ToString()

                    $headers = @{}
                    foreach ($line in ($text -split "`r?`n")) {
                        if ($line -match '^([^:]+):\s*(.+)$') {
                            $headers[$Matches[1].ToUpper()] = $Matches[2].Trim()
                        }
                    }
                    $loc = $headers['LOCATION']
                    if (-not $loc) { continue }
                    $key = "$ip|$loc"
                    if ($seen.ContainsKey($key)) { continue }
                    $seen[$key] = $true

                    $allResponses += @{
                        ipAddress = $ip
                        location  = $loc
                        server    = $headers['SERVER']
                        st        = $headers['ST']
                    }
                } catch [System.Net.Sockets.SocketException] {
                    # タイムアウトは正常
                }
            }
        } catch {
            Write-Warn2 "SSDP送信失敗 ($localAddr): $_"
        } finally {
            if ($client) { try { $client.Close() } catch { } }
        }
    }
    Write-Ok "SSDP 応答: $($allResponses.Count) 件"

    # デバイス記述XMLを取得
    $devices = @()
    foreach ($r in $allResponses) {
        try {
            $xmlResponse = Invoke-SafeLocalHttpRequest `
                -Uri $r.location `
                -ExpectedIp $r.ipAddress `
                -TimeoutSec 3 `
                -MaxResponseChars 1048576
            $doc = ConvertFrom-SafeXml -Text $xmlResponse.content -MaxChars 1048576
            $dev = $doc.root.device
            if (-not $dev) { continue }
            $devices += [ordered]@{
                ipAddress        = $r.ipAddress
                location         = $r.location
                server           = $r.server
                deviceType       = "$($dev.deviceType)"
                friendlyName     = "$($dev.friendlyName)"
                manufacturer     = "$($dev.manufacturer)"
                manufacturerURL  = "$($dev.manufacturerURL)"
                modelName        = "$($dev.modelName)"
                modelNumber      = "$($dev.modelNumber)"
                modelDescription = "$($dev.modelDescription)"
                serialNumber     = "$($dev.serialNumber)"
            }
        } catch {
            $devices += [ordered]@{
                ipAddress  = $r.ipAddress
                location   = $r.location
                server     = $r.server
                deviceType = $r.st
            }
        }
    }
    Write-Ok "SSDP 機器詳細: $($devices.Count) 件取得"
    return @($devices)
}

# ==========================================
# 2.2 UPnP IGD（インターネット ゲートウェイ デバイス）から WAN 情報を取得
#   XG-200KI 専用の管理画面スクレイピングと違い、IGD は認証なしの標準 API なので
#   Buffalo / NEC / TP-Link など UPnP 対応ルータなら機種を問わず外部IP・回線速度・
#   WAN 転送量が取れる。取得できない機種は素通り（失敗しても図の生成は続行）。
# ==========================================
function Find-UpnpService {
    # デバイス記述 XML を再帰的にたどり、指定サービスの controlURL を探す
    param($DeviceNode, [string]$TypePattern)
    if ($null -eq $DeviceNode) { return $null }
    foreach ($svc in @($DeviceNode.serviceList.service)) {
        if ("$($svc.serviceType)" -match $TypePattern) {
            return @{ serviceType = "$($svc.serviceType)"; controlURL = "$($svc.controlURL)" }
        }
    }
    foreach ($child in @($DeviceNode.deviceList.device)) {
        $r = Find-UpnpService -DeviceNode $child -TypePattern $TypePattern
        if ($r) { return $r }
    }
    return $null
}

function Invoke-UpnpAction {
    # 引数なしの SOAP アクションを叩き、応答の出力引数を hashtable で返す
    param(
        [string]$ControlUrl,
        [string]$ExpectedIp,
        [string]$ServiceType,
        [ValidateSet(
            'GetExternalIPAddress',
            'GetStatusInfo',
            'GetConnectionTypeInfo',
            'GetCommonLinkProperties',
            'GetTotalBytesSent',
            'GetTotalBytesReceived'
        )]
        [string]$Action,
        [int]$TimeoutSec = 4
    )
    if (-not $ServiceType -or $ServiceType.Length -gt 256 -or $ServiceType -notmatch '^urn:[A-Za-z0-9_.:-]+$') {
        return $null
    }
    $body = @"
<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body><u:$Action xmlns:u="$ServiceType"></u:$Action></s:Body>
</s:Envelope>
"@
    try {
        $response = Invoke-SafeLocalHttpRequest `
            -Uri $ControlUrl `
            -ExpectedIp $ExpectedIp `
            -Method POST `
            -Body $body `
            -Headers @{ SOAPAction = """$ServiceType#$Action""" } `
            -ContentType 'text/xml; charset="utf-8"' `
            -TimeoutSec $TimeoutSec `
            -MaxResponseChars 262144
        $x = ConvertFrom-SafeXml -Text $response.content -MaxChars 262144
        $bodyNode = @($x.DocumentElement.ChildNodes | Where-Object { $_.LocalName -eq 'Body' })[0]
        if (-not $bodyNode) { return $null }
        $respNode = @($bodyNode.ChildNodes)[0]
        if (-not $respNode) { return $null }
        $out = @{}
        foreach ($n in $respNode.ChildNodes) { $out[$n.LocalName] = $n.InnerText }
        return $out
    } catch {
        return $null
    }
}

function Get-IgdWanInfo {
    param($SsdpResponses, $GatewayIps, [int]$TimeoutSec = 4)
    Write-Step "UPnP IGD から WAN 情報を取得中..."

    # ゲートウェイか、IGD を名乗る応答だけを対象にする
    $candidates = @()
    foreach ($s in @($SsdpResponses)) {
        if (-not $s.location) { continue }
        $isGw  = $GatewayIps -contains $s.ipAddress
        $isIgd = "$($s.deviceType)" -match 'InternetGatewayDevice'
        if ($isGw -or $isIgd) { $candidates += $s }
    }
    $seenLoc = @{}
    foreach ($c in $candidates) {
        if ($seenLoc.ContainsKey($c.location)) { continue }
        $seenLoc[$c.location] = $true
        try {
            $xmlResponse = Invoke-SafeLocalHttpRequest `
                -Uri $c.location `
                -ExpectedIp $c.ipAddress `
                -TimeoutSec $TimeoutSec `
                -MaxResponseChars 1048576
            $doc = ConvertFrom-SafeXml -Text $xmlResponse.content -MaxChars 1048576
            $root = $doc.root.device
            if (-not $root) { continue }

            $conn = Find-UpnpService -DeviceNode $root -TypePattern 'WAN(IP|PPP)Connection'
            $comm = Find-UpnpService -DeviceNode $root -TypePattern 'WANCommonInterfaceConfig'
            if (-not $conn -and -not $comm) { continue }

            # controlURL は相対パスのことが多いので LOCATION を基準に絶対化する
            $baseUri = [Uri]$c.location
            $toAbs = {
                param([string]$U)
                if (-not $U) { return $null }
                if ($U -match '^https?://') { return $U }
                return (New-Object Uri($baseUri, $U)).AbsoluteUri
            }

            $info = [ordered]@{
                source          = "UPnP IGD"
                routerIp        = $c.ipAddress
                fetchedAt       = (Get-Date).ToString("o")
                friendlyName    = [string]$root.friendlyName
                manufacturer    = [string]$root.manufacturer
                modelName       = [string]$root.modelName
                externalIp      = $null
                connectionType  = $null
                connectionStatus = $null
                uptimeSec       = $null
                lastError       = $null
                wanAccessType   = $null
                upstreamKbps    = $null
                downstreamKbps  = $null
                physicalLinkStatus = $null
                totalBytesSent     = $null
                totalBytesReceived = $null
            }

            if ($conn) {
                $cu = & $toAbs $conn.controlURL
                $r1 = Invoke-UpnpAction -ControlUrl $cu -ExpectedIp $c.ipAddress -ServiceType $conn.serviceType -Action 'GetExternalIPAddress' -TimeoutSec $TimeoutSec
                # 未接続のルータは 0.0.0.0 を返す。IP が取れたかのように見せない
                if ($r1 -and $r1['NewExternalIPAddress'] -and $r1['NewExternalIPAddress'] -ne '0.0.0.0') {
                    $info.externalIp = $r1['NewExternalIPAddress']
                }
                $r2 = Invoke-UpnpAction -ControlUrl $cu -ExpectedIp $c.ipAddress -ServiceType $conn.serviceType -Action 'GetStatusInfo' -TimeoutSec $TimeoutSec
                if ($r2) {
                    $info.connectionStatus = $r2['NewConnectionStatus']
                    $info.lastError        = $r2['NewLastConnectionError']
                    if ($r2['NewUptime']) { $info.uptimeSec = [int64]$r2['NewUptime'] }
                }
                $r3 = Invoke-UpnpAction -ControlUrl $cu -ExpectedIp $c.ipAddress -ServiceType $conn.serviceType -Action 'GetConnectionTypeInfo' -TimeoutSec $TimeoutSec
                if ($r3) { $info.connectionType = $r3['NewConnectionType'] }
            }

            if ($comm) {
                $mu = & $toAbs $comm.controlURL
                $r4 = Invoke-UpnpAction -ControlUrl $mu -ExpectedIp $c.ipAddress -ServiceType $comm.serviceType -Action 'GetCommonLinkProperties' -TimeoutSec $TimeoutSec
                if ($r4) {
                    $info.wanAccessType      = $r4['NewWANAccessType']
                    $info.physicalLinkStatus = $r4['NewPhysicalLinkStatus']
                    if ($r4['NewLayer1UpstreamMaxBitRate'])   { $info.upstreamKbps   = [int64]([double]$r4['NewLayer1UpstreamMaxBitRate'] / 1000) }
                    if ($r4['NewLayer1DownstreamMaxBitRate']) { $info.downstreamKbps = [int64]([double]$r4['NewLayer1DownstreamMaxBitRate'] / 1000) }
                }
                $r5 = Invoke-UpnpAction -ControlUrl $mu -ExpectedIp $c.ipAddress -ServiceType $comm.serviceType -Action 'GetTotalBytesSent' -TimeoutSec $TimeoutSec
                if ($r5 -and $r5['NewTotalBytesSent']) { $info.totalBytesSent = [int64]$r5['NewTotalBytesSent'] }
                $r6 = Invoke-UpnpAction -ControlUrl $mu -ExpectedIp $c.ipAddress -ServiceType $comm.serviceType -Action 'GetTotalBytesReceived' -TimeoutSec $TimeoutSec
                if ($r6 -and $r6['NewTotalBytesReceived']) { $info.totalBytesReceived = [int64]$r6['NewTotalBytesReceived'] }
            }

            if ($info.externalIp -or $info.connectionStatus -or $info.wanAccessType) {
                Write-Ok "IGD WAN 情報を取得: 外部IP=$($info.externalIp) 状態=$($info.connectionStatus)"
                return [PSCustomObject]$info
            }
        } catch {
            Write-Warn2 "IGD 照会に失敗 ($($c.ipAddress)): $($_.Exception.Message.Split([Environment]::NewLine)[0])"
        }
    }
    Write-Warn2 "UPnP IGD からは WAN 情報を取得できませんでした（未対応/無効の可能性）"
    return $null
}

# ==========================================
# 2.5 mDNS / DNS-SD (Bonjour)
#   iPhone / Mac / Chromecast / プリンタは SSDP に応答しないことが多いが mDNS では名乗る。
#   Apple 系はプライバシー用のランダム MAC で OUI が引けないため、ここが唯一の手掛かりになる。
#   管理者権限不要: 224.0.0.251:5353 へ QU(ユニキャスト応答要求)クエリを投げ、
#   一時ポートで応答を受ける（5353 を Bind しないので Bonjour サービスと衝突しない）。
# ==========================================

# 問い合わせるサービス型。_services._dns-sd._udp は「対応サービスの一覧」を返す特別な型。
$script:MdnsServiceTypes = @(
    '_services._dns-sd._udp.local'
    '_device-info._tcp.local'      # モデル名 (MacBookPro18,3 など)
    '_companion-link._tcp.local'   # iPhone / iPad / Mac
    '_rdlink._tcp.local'           # Apple 端末間リンク
    '_airplay._tcp.local'
    '_raop._tcp.local'             # AirPlay オーディオ (Apple TV / HomePod)
    '_googlecast._tcp.local'       # Chromecast / Google Nest
    '_workstation._tcp.local'      # Linux / Samba
    '_smb._tcp.local'
    '_afpovertcp._tcp.local'
    '_ipp._tcp.local'              # プリンタ
    '_ipps._tcp.local'
    '_printer._tcp.local'
    '_pdl-datastream._tcp.local'
    '_scanner._tcp.local'
    '_hap._tcp.local'              # HomeKit アクセサリ
    '_spotify-connect._tcp.local'
    '_sonos._tcp.local'
    '_amzn-wplay._tcp.local'       # Fire TV
    '_nvstream._tcp.local'         # NVIDIA Shield / GameStream
    '_http._tcp.local'
)

function New-MdnsQuery {
    # 複数サービス型をまとめて 1 パケットに詰めた PTR クエリを組み立てる
    param([string[]]$Names)
    $buf = New-Object System.Collections.Generic.List[byte]
    $buf.AddRange([byte[]]@(0, 0, 0, 0))                              # ID=0, Flags=0 (standard query)
    $buf.Add([byte](([int]$Names.Count -shr 8) -band 0xFF))           # QDCOUNT
    $buf.Add([byte]([int]$Names.Count -band 0xFF))
    $buf.AddRange([byte[]]@(0, 0, 0, 0, 0, 0))                        # ANCOUNT / NSCOUNT / ARCOUNT
    foreach ($n in $Names) {
        foreach ($label in $n.Split('.')) {
            if (-not $label) { continue }
            $lb = [System.Text.Encoding]::UTF8.GetBytes($label)
            $buf.Add([byte]$lb.Length)
            $buf.AddRange($lb)
        }
        $buf.Add(0)
        # QTYPE=PTR(12) / QCLASS=IN(1) + unicast-response ビット(0x8000)
        $buf.AddRange([byte[]]@(0, 12, 0x80, 1))
    }
    return $buf.ToArray()
}

function Read-DnsName {
    # DNS 名を読む。0xC0 圧縮ポインタに追従する（追従した場合 Offset はポインタの直後で止める）
    param([byte[]]$Data, [ref]$Offset)
    $parts = @()
    $jumped = $false
    $i = $Offset.Value
    $guard = 0
    while ($i -lt $Data.Length -and $guard -lt 128) {
        $guard++
        $len = $Data[$i]
        if ($len -eq 0) { $i++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($i + 1 -ge $Data.Length) { break }
            # PowerShell の -shl は左辺の型幅でシフト量がマスクされるため、
            # byte のまま 8 ビット左シフトすると上位バイトが消える。必ず [int] 化する
            $ptr = ((([int]$len -band 0x3F) -shl 8) -bor [int]$Data[$i + 1])
            if (-not $jumped) { $Offset.Value = $i + 2; $jumped = $true }
            if ($ptr -ge $Data.Length) { break }
            $i = $ptr
            continue
        }
        if ($i + 1 + $len -gt $Data.Length) { break }
        $parts += [System.Text.Encoding]::UTF8.GetString($Data, $i + 1, $len)
        $i += 1 + $len
    }
    if (-not $jumped) { $Offset.Value = $i }
    return ($parts -join '.')
}

function Read-DnsRecords {
    # DNS 応答パケットから A / PTR / SRV / TXT レコードを取り出す
    param([byte[]]$Data)
    $recs = @()
    if ($null -eq $Data -or $Data.Length -lt 12) { return $recs }
    # byte のまま -shl すると上位バイトが消えるので [int] 化してから組み立てる
    $qd = (([int]$Data[4] -shl 8) -bor [int]$Data[5])
    $rrCount = (([int]$Data[6] -shl 8) -bor [int]$Data[7]) +
               (([int]$Data[8] -shl 8) -bor [int]$Data[9]) +
               (([int]$Data[10] -shl 8) -bor [int]$Data[11])
    $off = 12
    for ($q = 0; $q -lt $qd; $q++) {
        $o = [ref]$off
        [void](Read-DnsName -Data $Data -Offset $o)
        $off = $o.Value + 4
        if ($off -gt $Data.Length) { return $recs }
    }
    for ($r = 0; $r -lt $rrCount; $r++) {
        if ($off + 10 -gt $Data.Length) { break }
        $o = [ref]$off
        $name = Read-DnsName -Data $Data -Offset $o
        $off = $o.Value
        if ($off + 10 -gt $Data.Length) { break }
        $type  = (([int]$Data[$off] -shl 8) -bor [int]$Data[$off + 1])
        $rdlen = (([int]$Data[$off + 8] -shl 8) -bor [int]$Data[$off + 9])
        $off += 10
        if ($off + $rdlen -gt $Data.Length) { break }
        $value = $null
        switch ($type) {
            1 {   # A
                if ($rdlen -eq 4) { $value = "$($Data[$off]).$($Data[$off+1]).$($Data[$off+2]).$($Data[$off+3])" }
            }
            12 {  # PTR
                # [ref]$off を直接渡すと Read-DnsName が $off を進めてしまい、
                # 後段の "$off += $rdlen" と二重加算になるので作業用変数を使う
                $ptrOff = $off
                $po = [ref]$ptrOff
                $value = Read-DnsName -Data $Data -Offset $po
            }
            33 {  # SRV: priority/weight/port の 6 バイト後に target 名
                if ($rdlen -gt 6) {
                    $srvOff = $off + 6
                    $so = [ref]$srvOff
                    $value = Read-DnsName -Data $Data -Offset $so
                }
            }
            16 {  # TXT: 長さ付き文字列の並び
                $txt = @()
                $p = $off
                $end = $off + $rdlen
                while ($p -lt $end) {
                    $l = $Data[$p]
                    if ($l -eq 0 -or ($p + 1 + $l) -gt $end) { break }
                    $txt += [System.Text.Encoding]::UTF8.GetString($Data, $p + 1, $l)
                    $p += 1 + $l
                }
                $value = $txt
            }
        }
        $off += $rdlen
        $recs += @{ name = $name; type = $type; value = $value }
    }
    return $recs
}

function Get-MdnsServiceType {
    # "Living Room._googlecast._tcp.local" → "_googlecast._tcp"
    param([string]$Name)
    if (-not $Name) { return $null }
    if ($Name -match '(_[^._]+\._(?:tcp|udp))\.local\.?$') { return $Matches[1] }
    return $null
}

function Get-MdnsInstanceLabel {
    # "Living Room._googlecast._tcp.local" → "Living Room"
    param([string]$Name)
    if (-not $Name) { return $null }
    if ($Name -match '^(.+?)\._[^._]+\._(?:tcp|udp)\.local\.?$') { return $Matches[1] }
    return $null
}

function Invoke-MdnsDiscovery {
    param(
        [int]$TimeoutSec = 4,
        [string[]]$LocalIPs = @()
    )
    Write-Step "mDNS/Bonjour デバイスを探索中（${TimeoutSec}秒）..."

    $bindList = @()
    foreach ($ip in $LocalIPs) {
        try { $bindList += [System.Net.IPAddress]::Parse($ip) } catch { }
    }
    if ($bindList.Count -eq 0) { $bindList = @([System.Net.IPAddress]::Any) }

    $query    = New-MdnsQuery -Names $script:MdnsServiceTypes
    $mcastEp  = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('224.0.0.251'), 5353)

    $hostByIp = @{}   # A レコード由来: ipv4 → ホスト名(.local を除去)
    $svcByIp  = @{}   # 応答元 ip → サービス型の集合
    $txtByIp  = @{}   # 応答元 ip → TXT の key/value
    $nameByIp = @{}   # 応答元 ip → インスタンス名（人が付けた名前）

    foreach ($localAddr in $bindList) {
        $client = $null
        try {
            $client = New-Object System.Net.Sockets.UdpClient
            $client.Client.SetSocketOption([System.Net.Sockets.SocketOptionLevel]::Socket,
                                           [System.Net.Sockets.SocketOptionName]::ReuseAddress, $true)
            # 5353 を Bind できれば、QU を無視してマルチキャストで返す機器の応答も拾える。
            # 既存の Bonjour レスポンダと競合して失敗する環境では一時ポートに落とす
            # （その場合は QU 応答＝ユニキャストで返す機器のみ拾える）。
            $onMdnsPort = $false
            try {
                $client.Client.Bind((New-Object System.Net.IPEndPoint($localAddr, 5353)))
                $onMdnsPort = $true
            } catch {
                $client.Client.Bind((New-Object System.Net.IPEndPoint($localAddr, 0)))
            }
            if ($onMdnsPort) {
                try { $client.JoinMulticastGroup([System.Net.IPAddress]::Parse('224.0.0.251'), $localAddr) } catch { }
            }
            $client.Client.ReceiveTimeout = 800
            try { $client.Ttl = 255 } catch { }

            $portNote = if ($onMdnsPort) { '5353' } else { '一時ポート' }
            Write-Host "  -> $localAddr から mDNS クエリ送信 ($portNote)" -ForegroundColor Gray
            [void]$client.Send($query, $query.Length, $mcastEp)
            Start-Sleep -Milliseconds 400
            [void]$client.Send($query, $query.Length, $mcastEp)

            $end = (Get-Date).AddSeconds($TimeoutSec)
            while ((Get-Date) -lt $end) {
                try {
                    $remoteEp = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                    $data = $client.Receive([ref]$remoteEp)
                    $srcIp = $remoteEp.Address.ToString()
                    foreach ($rec in (Read-DnsRecords -Data $data)) {
                        switch ($rec.type) {
                            1 {
                                if ($rec.value -and $rec.name) {
                                    $hn = ($rec.name -replace '\.local\.?$', '')
                                    if ($hn) { $hostByIp[[string]$rec.value] = $hn }
                                }
                            }
                            12 {
                                $svc = Get-MdnsServiceType -Name $rec.name
                                if ($svc -and $svc -ne '_services._dns-sd._udp') {
                                    if (-not $svcByIp.ContainsKey($srcIp)) { $svcByIp[$srcIp] = @{} }
                                    $svcByIp[$srcIp][$svc] = $true
                                }
                                $inst = Get-MdnsInstanceLabel -Name ([string]$rec.value)
                                if ($inst -and -not $nameByIp.ContainsKey($srcIp)) { $nameByIp[$srcIp] = $inst }
                            }
                            33 {
                                $svc = Get-MdnsServiceType -Name $rec.name
                                if ($svc) {
                                    if (-not $svcByIp.ContainsKey($srcIp)) { $svcByIp[$srcIp] = @{} }
                                    $svcByIp[$srcIp][$svc] = $true
                                }
                                $inst = Get-MdnsInstanceLabel -Name $rec.name
                                if ($inst -and -not $nameByIp.ContainsKey($srcIp)) { $nameByIp[$srcIp] = $inst }
                            }
                            16 {
                                if (-not $txtByIp.ContainsKey($srcIp)) { $txtByIp[$srcIp] = @{} }
                                foreach ($kv in @($rec.value)) {
                                    if ("$kv" -match '^([^=]+)=(.*)$') {
                                        $k = $Matches[1].ToLower()
                                        if (-not $txtByIp[$srcIp].ContainsKey($k)) { $txtByIp[$srcIp][$k] = $Matches[2] }
                                    }
                                }
                            }
                        }
                    }
                } catch [System.Net.Sockets.SocketException] {
                    # 受信タイムアウトは正常（応答が途切れただけ）
                }
            }
        } catch {
            Write-Warn2 "mDNS 送信失敗 ($localAddr): $($_.Exception.Message)"
        } finally {
            if ($client) { try { $client.Close() } catch { } }
        }
    }

    # IP ごとに集約
    $allIps = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $hostByIp.Keys) { [void]$allIps.Add($k) }
    foreach ($k in $svcByIp.Keys)  { [void]$allIps.Add($k) }
    foreach ($k in $txtByIp.Keys)  { [void]$allIps.Add($k) }
    foreach ($k in $nameByIp.Keys) { [void]$allIps.Add($k) }

    $result = @{}
    foreach ($ip in $allIps) {
        $txt = if ($txtByIp.ContainsKey($ip)) { $txtByIp[$ip] } else { @{} }
        # モデル名は機器ごとに載るキーが違う: model=Mac/iOS, md=Chromecast, am=AirPlay, usb_mdl/ty=プリンタ
        $model = @('model', 'md', 'am', 'usb_mdl', 'ty', 'product') |
                 ForEach-Object { if ($txt.ContainsKey($_)) { $txt[$_] } } |
                 Where-Object { $_ } | Select-Object -First 1
        $friendly = @('fn', 'n') |
                    ForEach-Object { if ($txt.ContainsKey($_)) { $txt[$_] } } |
                    Where-Object { $_ } | Select-Object -First 1
        if (-not $friendly -and $nameByIp.ContainsKey($ip)) { $friendly = $nameByIp[$ip] }
        $services = if ($svcByIp.ContainsKey($ip)) { @($svcByIp[$ip].Keys | Sort-Object) } else { @() }
        $hostName = if ($hostByIp.ContainsKey($ip)) { $hostByIp[$ip] } else { $null }
        if (-not $hostName -and -not $friendly -and $services.Count -eq 0) { continue }
        $result[$ip] = @{
            hostname     = $hostName
            friendlyName = $friendly
            model        = $model
            services     = $services
        }
    }
    Write-Ok "mDNS 応答: $($result.Count) 台"
    return $result
}

# ==========================================
# 3. NetBIOS
# ==========================================
function ConvertFrom-NbtstatOutput {
    # nbtstat -A の出力を解釈する。日本語版・英語版の両方のラベルに対応。
    # nbtstat の呼び出しから分離してあるのは、この解釈部分をテストできるようにするため。
    param([string]$Output)
    if ([string]::IsNullOrWhiteSpace($Output)) { return $null }
    $output = $Output
        if ($output -match 'Host not found|ホストが見つかりません|応答なし|タイムアウト') {
            return $null
        }
        if ($output -notmatch '<00>') { return $null }

        $info = @{}
        # コンピュータ名 = <00> + UNIQUE/一意
        if ($output -match '(?m)^\s*(\S+)\s*<00>\s*(?:UNIQUE|一意)') {
            $info.name = $Matches[1].Trim()
        }
        # ワークグループ = <00> + GROUP/グループ
        if ($output -match '(?m)^\s*(\S+)\s*<00>\s*(?:GROUP|グループ)') {
            $info.workgroup = $Matches[1].Trim()
        }
        # MAC
        if ($output -match 'MAC[^=]*=\s*([0-9A-Fa-f\-]{17})') {
            $info.mac = $Matches[1]
        }
        if ($info.Count -gt 0) { return $info }
    return $null
}

function Get-NetbiosInfo {
    param([string]$Ip)
    try {
        $output = & nbtstat -A $Ip 2>&1 | Out-String
        return ConvertFrom-NbtstatOutput -Output $output
    } catch { }
    return $null
}

# ==========================================
# 4. HTTP Banner
# ==========================================
function Get-HttpFingerprint {
    param([string]$Ip, [int]$TimeoutSec = 3)

    $patterns = @{
        'Buffalo' = '(?i)buffalo|airstation'
        'NEC Aterm' = '(?i)aterm'
        'TP-Link' = '(?i)tp-?link'
        'ASUS' = '(?i)asus'
        'NETGEAR' = '(?i)netgear'
        'Synology' = '(?i)synology'
        'QNAP' = '(?i)qnap'
        'HP' = '(?i)\bhp\b|hewlett'
        'Epson' = '(?i)epson'
        'Brother' = '(?i)brother\b'
        'Canon' = '(?i)canon'
        'Ricoh' = '(?i)ricoh'
        'ELECOM' = '(?i)elecom'
        'I-O DATA' = '(?i)i-?o\s?data|landisk'
        'Yamaha' = '(?i)yamaha|\brtx\d'
        'NTT HGW' = '(?i)\b(xg|pr|rt|rx)-\d{3,4}\s?(mi|ki|ne)\b'
    }
    # 応答テキストからベンダー候補とモデル番号を抽出する（200応答と401応答で共用）
    $extractBanner = {
        param([string]$Text)
        $hints = @()
        foreach ($k in $patterns.Keys) {
            if ($Text -match $patterns[$k]) { $hints += $k }
        }
        # 主要メーカーのモデル番号パターン (Buffalo/NEC/ELECOM/I-O DATA/Yamaha)
        $modelHint = $null
        if ($Text -match '\b(WSR|WCR|WHR|WXR|WTR|WMR|WEX)-[A-Z0-9]+\b') { $modelHint = $Matches[0] }
        elseif ($Text -match '\b(WG|WX|WR|PA-WG|PA-WX|PA-WR)\d+[A-Z0-9]*\b') { $modelHint = $Matches[0] }
        elseif ($Text -match '\b(WRC|WMC)-[A-Z0-9]+\b') { $modelHint = $Matches[0] }
        elseif ($Text -match '\bWN-[A-Z0-9]+\b') { $modelHint = $Matches[0] }
        elseif ($Text -match '\bRTX\d{3,4}\b') { $modelHint = $Matches[0] }
        elseif ($Text -match '\b(XG|PR|RT|RX)-\d{3,4}\s?(MI|KI|NE)\b') { $modelHint = ($Matches[0] -replace '\s', '') }
        return @{ hints = @($hints); modelHint = $modelHint }
    }

    foreach ($scheme in @('http', 'https')) {
        $address = $null
        if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$address)) { return $null }
        $uriHost = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { "[$Ip]" } else { $Ip }
        $url = "${scheme}://${uriHost}/"
        try {
            # LAN 機器の応答も信頼しない。別ホストへのリダイレクトは追わず、本文も上限付きで読む。
            # HTTPS は OS 標準の証明書検証を使い、自己署名証明書を黙って受け入れない。
            $response = Invoke-SafeLocalHttpRequest `
                -Uri $url `
                -ExpectedIp $Ip `
                -TimeoutSec $TimeoutSec `
                -MaxResponseChars 262144 `
                -AllowErrorResponse
            $server  = $response.headers['Server']
            $wwwAuth = $response.headers['WWW-Authenticate']
            $body = $response.content

            $title = $null
            if ($body -match '(?is)<title[^>]*>([^<]+)</title>') {
                $title = $Matches[1].Trim()
            }
            $banner = & $extractBanner "$server $wwwAuth $title $body"
            return @{
                scheme    = $scheme
                server    = $server
                title     = $title
                hints     = $banner.hints
                modelHint = $banner.modelHint
            }
        } catch { } # 接続失敗または証明書エラー → 次のスキーマ
    }
    return $null
}

# ==========================================
# 4.5 代表ポートの確認（軽量ポートスキャン）
#   開いているポートは「その機器が何なのか」を一番はっきり示す。
#   445 が開いていれば Windows/NAS、631 ならプリンタ、といった具合。
#   自宅ネットワーク向けの機能なので、対象は少数の代表ポートに絞り、
#   接続できたら即座に閉じる（サービスへの負荷をかけない）。
# ==========================================
$script:CommonPorts = @(
    @{ port = 22;   name = 'SSH';        hint = 'Linux / NAS / ルーター' }
    @{ port = 53;   name = 'DNS';        hint = 'ルーター / DNSサーバ' }
    @{ port = 80;   name = 'HTTP';       hint = '管理画面 / Webサーバ' }
    @{ port = 139;  name = 'NetBIOS';    hint = 'Windows / ファイル共有' }
    @{ port = 443;  name = 'HTTPS';      hint = '管理画面 / Webサーバ' }
    @{ port = 445;  name = 'SMB';        hint = 'Windows / NAS（ファイル共有）' }
    @{ port = 515;  name = 'LPD';        hint = 'プリンタ' }
    @{ port = 548;  name = 'AFP';        hint = 'Mac / NAS' }
    @{ port = 631;  name = 'IPP';        hint = 'プリンタ' }
    @{ port = 3389; name = 'RDP';        hint = 'Windows（リモートデスクトップ）' }
    @{ port = 5000; name = 'UPnP/NAS';   hint = 'NAS（Synology 等）' }
    @{ port = 8080; name = 'HTTP代替';   hint = '管理画面 / アプリ' }
    @{ port = 9100; name = 'RAW印刷';    hint = 'プリンタ' }
)

function Test-TcpPort {
    param([string]$Ip, [int]$Port, [int]$TimeoutMs = 400)
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $task = $tcp.ConnectAsync($Ip, $Port)
        if (-not $task.Wait($TimeoutMs)) { return $false }
        return $tcp.Connected
    } catch {
        return $false
    } finally {
        if ($tcp) { try { $tcp.Close() } catch { } }
    }
}

function Get-OpenPorts {
    param([string]$Ip, [int]$TimeoutMs = 400)
    $open = @()
    foreach ($p in $script:CommonPorts) {
        if (Test-TcpPort -Ip $Ip -Port $p.port -TimeoutMs $TimeoutMs) {
            $open += [PSCustomObject]@{ port = $p.port; service = $p.name; hint = $p.hint }
        }
    }
    return @($open)
}

# ==========================================
# 5. デバイス種別推定
# ==========================================
function Get-DeviceTypeGuess {
    param($Vendor, $Ssdp, $Netbios, $Http, $IsGateway, $Mdns, $Ports)
    $text = ""
    if ($Vendor)  { $text += " $Vendor" }
    if ($Ssdp)    { $text += " $($Ssdp.deviceType) $($Ssdp.modelName) $($Ssdp.friendlyName) $($Ssdp.manufacturer)" }
    if ($Http)    { $text += " $($Http.server) $($Http.title) $($Http.hints -join ' ')" }
    if ($Mdns)    { $text += " $($Mdns.hostname) $($Mdns.friendlyName) $($Mdns.model)" }

    if ($IsGateway)                                                                            { return "router" }

    # mDNS のサービス型は「何の機器か」を最も確実に示すので、テキスト推定より先に判定する
    if ($Mdns -and @($Mdns.services).Count -gt 0) {
        $svc = " " + (@($Mdns.services) -join ' ') + " "
        if ($svc -match '_ipps?\b|_printer\b|_pdl-datastream\b|_scanner\b')  { return "printer" }
        if ($svc -match '_googlecast\b|_amzn-wplay\b|_nvstream\b')           { return "tv" }
        if ($svc -match '_airplay\b|_raop\b') {
            # iPhone/iPad は _companion-link を併せて出す。単独なら Apple TV / HomePod。
            if ($svc -match '_companion-link\b|_rdlink\b') { return "apple" }
            return "tv"
        }
        if ($svc -match '_companion-link\b|_rdlink\b')                       { return "apple" }
        if ($svc -match '_spotify-connect\b|_sonos\b|_hap\b')                { return "iot" }
        if ($svc -match '_afpovertcp\b')                                     { return "nas" }
        if ($svc -match '_workstation\b|_smb\b')                             { return "pc" }
    }

    # 開いているポートも「何の機器か」を強く示す。mDNS の次に信頼する
    if ($Ports -and @($Ports).Count -gt 0) {
        $pl = @($Ports | ForEach-Object { [int]$_.port })
        if ($pl -contains 631 -or $pl -contains 9100 -or $pl -contains 515) { return "printer" }
        if ($pl -contains 3389)                                             { return "pc" }
        if (($pl -contains 5000) -and ($pl -contains 445))                  { return "nas" }
        if ($pl -contains 548)                                              { return "nas" }
        if ($pl -contains 445 -or $pl -contains 139)                        { return "pc" }
    }

    if ($text -match '(?i)InternetGatewayDevice|airstation|aterm|wireless\s*router')           { return "router" }
    if ($text -match '(?i)mediarenderer|television|smart\s*tv|chromecast|airplay|roku|bravia') { return "tv" }
    if ($text -match '(?i)playstation|xbox|nintendo')                                          { return "console" }
    if ($text -match '(?i)printer|laserjet|deskjet|ipp|epson|brother|canon|ricoh')             { return "printer" }
    if ($text -match '(?i)synology|qnap|drobo|terastation|nas\b')                              { return "nas" }
    if ($text -match '(?i)\bapple|iphone|ipad|macbook')                                        { return "apple" }
    if ($text -match '(?i)samsung|xiaomi|huawei|oneplus|google\s*pixel')                       { return "phone" }
    if ($text -match '(?i)espressif|tuya|esp\d|raspberry')                                     { return "iot" }
    if ($Netbios -and $Netbios.name)                                                           { return "pc" }
    return "unknown"
}

# ==========================================
# Main
# ==========================================
if (-not (Test-Path $InputPath)) {
    throw "入力ファイルが見つかりません: $InputPath。先に Collect-NetworkInfo.ps1 を実行してください。"
}

Write-Host "=========================================" -ForegroundColor Magenta
Write-Host " Network Topology Mapper - Identifier" -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta

# JSON は PSCustomObject のまま扱う（PS 5.1 の OrderedDictionary シリアライズバグを回避）
$rawJson = Get-Content $InputPath -Raw -Encoding UTF8
$data = $rawJson | ConvertFrom-Json

if (-not $AllowedCidrs -or @($AllowedCidrs).Count -eq 0) {
    $AllowedCidrs = @($data.scanScope.allowedCidrs | Where-Object { $_ })
}
if (-not $AllowedCidrs -or @($AllowedCidrs).Count -eq 0) {
    throw '機器特定には -AllowedCidrs が必要です。Run-NetworkMapper.ps1 -DetailedScan から実行してください。'
}
foreach ($cidr in @($AllowedCidrs)) {
    $cidrParts = $cidr -split '/', 2
    $cidrPrefix = if ($cidrParts.Count -eq 2 -and $cidrParts[1] -match '^\d+$') { [int]$cidrParts[1] } else { -1 }
    if ($cidrParts.Count -ne 2 -or $cidrPrefix -lt 22 -or $cidrPrefix -gt 30 -or
        -not (Test-PrivateIpv4Address -IpAddress $cidrParts[0]) -or
        -not (Test-Ipv4InCidr -IpAddress $cidrParts[0] -Cidr $cidr)) {
        throw "許可 CIDR の形式が不正です: $cidr"
    }
}
$AllowedCidrs = @($AllowedCidrs | Sort-Object -Unique)
Write-Host "許可された調査範囲: $($AllowedCidrs -join ', ')" -ForegroundColor DarkGray

# 対象 IP リストを構築
$targetIps  = New-Object System.Collections.Generic.HashSet[string]
$gatewayIps = New-Object System.Collections.Generic.HashSet[string]
foreach ($a in $data.adapters) {
    if ($a.ipv4Gateway -and (Test-IpInAllowedCidrs -IpAddress $a.ipv4Gateway -Cidrs $AllowedCidrs)) {
        [void]$targetIps.Add($a.ipv4Gateway)
        [void]$gatewayIps.Add($a.ipv4Gateway)
    }
}
foreach ($n in $data.neighbors) {
    if ($n.ipAddress -and (Test-IpInAllowedCidrs -IpAddress $n.ipAddress -Cidrs $AllowedCidrs)) {
        [void]$targetIps.Add($n.ipAddress)
    }
}
foreach ($h in $data.discoveredHosts) {
    if ($h.ipAddress -and (Test-IpInAllowedCidrs -IpAddress $h.ipAddress -Cidrs $AllowedCidrs)) {
        [void]$targetIps.Add($h.ipAddress)
    }
}

# マルチキャスト送信元にする自 IP（SSDP / mDNS で共用）
$localIps = @()
foreach ($a in $data.adapters) {
    foreach ($ipObj in $a.ipv4Addresses) {
        $addr = $ipObj.address
        if ($addr -and (Test-IpInAllowedCidrs -IpAddress $addr -Cidrs $AllowedCidrs)) {
            $localIps += $addr
        }
    }
}

# 1. SSDP
$ssdpDevicesArr = @()
$ssdpByIp = @{}
if (-not $SkipSsdp) {
    $ssdpDevicesArr = @(Invoke-SsdpDiscovery -TimeoutSec $SsdpTimeoutSec -LocalIPs $localIps |
        Where-Object { $_.ipAddress -and (Test-IpInAllowedCidrs -IpAddress $_.ipAddress -Cidrs $AllowedCidrs) })
    foreach ($s in $ssdpDevicesArr) {
        if ($s.ipAddress -and -not $ssdpByIp.ContainsKey($s.ipAddress)) {
            $ssdpByIp[$s.ipAddress] = $s
            [void]$targetIps.Add($s.ipAddress)
        }
    }
}

# 1.2 UPnP IGD の WAN 情報（SSDP の結果を再利用するので SSDP 実施時のみ）
$wanInfo = $null
if (-not $SkipIgd -and -not $SkipSsdp -and $ssdpDevicesArr.Count -gt 0) {
    $wanInfo = Get-IgdWanInfo -SsdpResponses $ssdpDevicesArr -GatewayIps @($gatewayIps) -TimeoutSec $HttpTimeoutSec
}

# 1.5 mDNS / Bonjour
$mdnsByIp = @{}
if (-not $SkipMdns) {
    $mdnsRaw = Invoke-MdnsDiscovery -TimeoutSec $MdnsTimeoutSec -LocalIPs $localIps
    foreach ($mip in @($mdnsRaw.Keys)) {
        if ($mip -and (Test-IpInAllowedCidrs -IpAddress $mip -Cidrs $AllowedCidrs)) {
            $mdnsByIp[$mip] = $mdnsRaw[$mip]
            [void]$targetIps.Add($mip)
        }
    }
}

# 2. OUI
$ouiDb = $null
if (-not $SkipOui) { $ouiDb = Get-OuiDatabase -CacheOnly:$NoExternalDownloads }

# 3. NetBIOS
$netbiosByIp = @{}
if (-not $SkipNetbios) {
    $nbIps = @($targetIps | Where-Object { $_ })
    if ($CanParallel -and $nbIps.Count -gt 1) {
        Write-Step "NetBIOS 名前解決（並列 x$ThrottleLimit）..."
        # 並列ランスペースには関数が引き継がれないので、依存する解析関数も一緒に渡す
        $nbDef = ${function:Get-NetbiosInfo}.ToString()
        $nbParseDef = ${function:ConvertFrom-NbtstatOutput}.ToString()
        $nbResults = $nbIps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            ${function:ConvertFrom-NbtstatOutput} = $using:nbParseDef
            ${function:Get-NetbiosInfo} = $using:nbDef
            $info = Get-NetbiosInfo -Ip $_
            if ($info) { [PSCustomObject]@{ ip = $_; info = $info } }
        }
        foreach ($r in $nbResults) { if ($r) { $netbiosByIp[$r.ip] = $r.info } }
    } else {
        Write-Step "NetBIOS 名前解決..."
        foreach ($ip in $nbIps) {
            $info = Get-NetbiosInfo -Ip $ip
            if ($info) { $netbiosByIp[$ip] = $info }
        }
    }
    Write-Ok "$($netbiosByIp.Count) 件 NetBIOS 解決"
}

# 4. HTTP (gateways + SSDP devices)
$httpByIp = @{}
if (-not $SkipHttp) {
    $httpTargets = New-Object System.Collections.Generic.HashSet[string]
    foreach ($g in $gatewayIps) { [void]$httpTargets.Add($g) }
    foreach ($s in $ssdpByIp.Keys) { [void]$httpTargets.Add($s) }
    $httpIps = @($httpTargets | Where-Object { $_ })
    $httpTo = $HttpTimeoutSec
    if ($CanParallel -and $httpIps.Count -gt 1) {
        Write-Step "HTTP フィンガープリンティング（並列 x$ThrottleLimit）..."
        $httpDef = ${function:Get-HttpFingerprint}.ToString()
        $safeUriDef = ${function:Test-SafeLocalHttpUri}.ToString()
        $limitedReadDef = ${function:Read-LimitedResponseText}.ToString()
        $safeRequestDef = ${function:Invoke-SafeLocalHttpRequest}.ToString()
        $httpResults = $httpIps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
            ${function:Test-SafeLocalHttpUri} = $using:safeUriDef
            ${function:Read-LimitedResponseText} = $using:limitedReadDef
            ${function:Invoke-SafeLocalHttpRequest} = $using:safeRequestDef
            ${function:Get-HttpFingerprint} = $using:httpDef
            $fp = Get-HttpFingerprint -Ip $_ -TimeoutSec $using:httpTo
            if ($fp) { [PSCustomObject]@{ ip = $_; fp = $fp } }
        }
        foreach ($r in $httpResults) { if ($r) { $httpByIp[$r.ip] = $r.fp } }
    } else {
        Write-Step "HTTP フィンガープリンティング..."
        foreach ($ip in $httpIps) {
            Write-Host "  -> $ip" -ForegroundColor Gray
            $fp = Get-HttpFingerprint -Ip $ip -TimeoutSec $httpTo
            if ($fp) { $httpByIp[$ip] = $fp }
        }
    }
    Write-Ok "$($httpByIp.Count) 件 HTTP 情報取得"
}

# 4.5 代表ポートの確認
$portsByIp = @{}
if (-not $SkipPortScan) {
    $scanIps = @($targetIps | Where-Object { $_ -and -not $gatewayIps.Contains($_) })
    # ゲートウェイは HTTP プローブで既に見ているが、種別判定のため含める
    foreach ($g in $gatewayIps) { if ($g) { $scanIps += $g } }
    $scanIps = @($scanIps | Sort-Object -Unique)

    if ($scanIps.Count -gt 0) {
        $portTo = $PortScanTimeoutMs
        if ($CanParallel -and $scanIps.Count -gt 1) {
            Write-Step "代表ポートを確認中（並列 x$ThrottleLimit、$($scanIps.Count) 台）..."
            $portsDef = ${function:Get-OpenPorts}.ToString()
            $testDef  = ${function:Test-TcpPort}.ToString()
            $portList = $script:CommonPorts
            $portResults = $scanIps | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
                # 並列ランスペースには関数も変数も引き継がれないので明示的に渡す
                ${function:Test-TcpPort}  = $using:testDef
                ${function:Get-OpenPorts} = $using:portsDef
                $script:CommonPorts = $using:portList
                $op = Get-OpenPorts -Ip $_ -TimeoutMs $using:portTo
                if (@($op).Count -gt 0) { [PSCustomObject]@{ ip = $_; ports = $op } }
            }
            foreach ($r in $portResults) { if ($r) { $portsByIp[$r.ip] = @($r.ports) } }
        } else {
            Write-Step "代表ポートを確認中（$($scanIps.Count) 台）..."
            foreach ($ip in $scanIps) {
                $op = Get-OpenPorts -Ip $ip -TimeoutMs $portTo
                if (@($op).Count -gt 0) { $portsByIp[$ip] = @($op) }
            }
        }
        $totalOpen = 0
        foreach ($k in $portsByIp.Keys) { $totalOpen += @($portsByIp[$k]).Count }
        Write-Ok "$($portsByIp.Count) 台で計 $totalOpen 個の開放ポートを検出"
    }
}

# 5. 統合 - 各 IP の指紋を Hashtable で構築し、後で PSCustomObject に変換
$macByIp = @{}
foreach ($n in $data.neighbors) {
    if ($n.macAddress -and $n.ipAddress) { $macByIp[$n.ipAddress] = $n.macAddress }
}

$fpHash = @{}
foreach ($ip in $targetIps) {
    if ([string]::IsNullOrEmpty($ip)) { continue }
    $mac = $macByIp[$ip]
    $vendor = $null
    if ($ouiDb -and $mac) { $vendor = Get-OuiVendor -Mac $mac -Db $ouiDb }
    $ssdp = $ssdpByIp[$ip]
    $nb = $netbiosByIp[$ip]
    $http = $httpByIp[$ip]
    $mdns = $mdnsByIp[$ip]
    $ports = $portsByIp[$ip]
    $isGw = $gatewayIps.Contains($ip)

    $sources = @()
    if ($vendor) { $sources += 'oui' }
    if ($ssdp)   { $sources += 'ssdp' }
    if ($mdns)   { $sources += 'mdns' }
    if ($nb)     { $sources += 'netbios' }
    if ($http)   { $sources += 'http' }
    if ($ports)  { $sources += 'port' }
    if ($sources.Count -eq 0) { continue }

    # PSCustomObject として作成（[ordered]@{} は PS 5.1 でシリアライズに不具合あり）
    $fpHash[$ip] = [PSCustomObject]@{
        vendor        = $vendor
        deviceType    = (Get-DeviceTypeGuess -Vendor $vendor -Ssdp $ssdp -Netbios $nb -Http $http -IsGateway $isGw -Mdns $mdns -Ports $ports)
        openPorts     = if ($ports) { @($ports) } else { $null }
        manufacturer  = if ($ssdp) { [string]$ssdp.manufacturer } else { $null }
        modelName     = if ($ssdp -and $ssdp.modelName) { [string]$ssdp.modelName } elseif ($mdns -and $mdns.model) { [string]$mdns.model } else { $null }
        mdnsName      = if ($mdns -and $mdns.hostname) { [string]$mdns.hostname } else { $null }
        mdnsFriendly  = if ($mdns -and $mdns.friendlyName) { [string]$mdns.friendlyName } else { $null }
        mdnsModel     = if ($mdns -and $mdns.model) { [string]$mdns.model } else { $null }
        mdnsServices  = if ($mdns -and @($mdns.services).Count -gt 0) { @($mdns.services) } else { $null }
        modelNumber   = if ($ssdp) { [string]$ssdp.modelNumber } else { $null }
        friendlyName  = if ($ssdp -and $ssdp.friendlyName) { [string]$ssdp.friendlyName } elseif ($mdns) { @($mdns.friendlyName, $mdns.hostname) | Where-Object { $_ } | Select-Object -First 1 } else { $null }
        serialNumber  = if ($ssdp) { [string]$ssdp.serialNumber } else { $null }
        netbiosName   = if ($nb -and $nb.name) { [string]$nb.name } else { $null }
        workgroup     = if ($nb -and $nb.workgroup) { [string]$nb.workgroup } else { $null }
        httpServer    = if ($http) { [string]$http.server } else { $null }
        httpTitle     = if ($http) { [string]$http.title } else { $null }
        httpHints     = if ($http -and $http.hints -and @($http.hints).Count -gt 0) { @($http.hints) } else { $null }
        httpModelHint = if ($http) { [string]$http.modelHint } else { $null }
        sources       = @($sources)
    }
}

# Hashtable → PSCustomObject (フラットなプロパティ群として保持)
$fpObj = New-Object PSCustomObject
foreach ($k in $fpHash.Keys) {
    $fpObj | Add-Member -NotePropertyName $k -NotePropertyValue $fpHash[$k] -Force
}

# 既存 PSCustomObject に追加プロパティを Add-Member で挿入
$mdnsArr = @()
foreach ($mip in ($mdnsByIp.Keys | Sort-Object)) {
    $m = $mdnsByIp[$mip]
    $mdnsArr += [PSCustomObject]@{
        ipAddress    = $mip
        hostname     = $m.hostname
        friendlyName = $m.friendlyName
        model        = $m.model
        services     = @($m.services)
    }
}

$data | Add-Member -NotePropertyName "ssdpDevices" -NotePropertyValue ([array]$ssdpDevicesArr) -Force
$data | Add-Member -NotePropertyName "mdnsDevices" -NotePropertyValue ([array]$mdnsArr) -Force
$data | Add-Member -NotePropertyName "wanInfo" -NotePropertyValue $wanInfo -Force
$data | Add-Member -NotePropertyName "deviceFingerprints" -NotePropertyValue $fpObj -Force

Write-Ok "デバイス指紋採取完了: $($fpHash.Count) 件"

# 保存
$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$data | ConvertTo-Json -Depth 10 | Set-Content $OutputPath -Encoding UTF8
Write-Host ""
Write-Ok "保存: $OutputPath"
