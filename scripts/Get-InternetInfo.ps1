<#
.SYNOPSIS
    インターネット側から見た自分の情報（グローバルIP、プロバイダ、AS番号、接続方式など）を収集する。

.DESCRIPTION
    「確認くん」系のサイトで分かる情報を、ブラウザを開かずに取得する。
    LAN 内の構成図や診断だけでは分からない「回線側」の素性を明らかにするのが目的:

      - グローバル IPv4 / IPv6（どちらで外に出ているか）
      - 逆引きホスト名（ここに接続方式の手掛かりが入っている）
      - プロバイダ名・AS 番号・割り当てプレフィックス
      - 接続方式の推定（PPPoE / IPoE / MAP-E / DS-Lite / モバイル）
      - traceroute の各ホップが，どの事業者(AS)を通っているか

    AS 情報は Team Cymru の DNS ベースのサービスを使う（API キー不要、
    HTTP より軽く、レート制限も緩い）。補足として RDAP も引く。

.PARAMETER OutputPath
    出力 JSON（既定: ..\output\internet-info.json）

.PARAMETER InputPath
    収集済みの network-data.json。traceroute と UPnP の情報を再利用する

.PARAMETER SkipRdap
    RDAP 参照を省く（応答が遅い環境向け）

.PARAMETER TimeoutSec
    HTTP のタイムアウト秒
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$PSScriptRoot\..\output\internet-info.json",
    [string]$InputPath  = "$PSScriptRoot\..\output\network-data.json",
    [switch]$SkipRdap,
    # NAT タイプ判定（STUN）を省く
    [switch]$SkipNat,
    [int]$TimeoutSec = 8
)

$ErrorActionPreference = "Continue"

function Write-Step  { param([string]$M) Write-Host "[*] $M" -ForegroundColor Cyan }
function Write-Ok    { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn2 { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }

# ==========================================
# グローバル IP の取得
# ==========================================
function Test-PublicInternetAddress {
    param([System.Net.IPAddress]$Address)
    if ($null -eq $Address -or [System.Net.IPAddress]::IsLoopback($Address)) { return $false }

    $bytes = $Address.GetAddressBytes()
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        # RFC1918、CGN、リンクローカル、文書用、ベンチマーク用、予約/マルチキャスト。
        if ($bytes[0] -eq 0 -or $bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224) { return $false }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $false }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -in @(0, 2)) { return $false }
        if ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) { return $false }
        if ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) { return $false }
        if ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113) { return $false }
        return $true
    }

    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($Address.Equals([System.Net.IPAddress]::IPv6Any)) { return $false }
        if ($Address.IsIPv6LinkLocal -or $Address.IsIPv6Multicast -or $Address.IsIPv6SiteLocal) { return $false }
        if (($bytes[0] -band 0xFE) -eq 0xFC) { return $false } # ULA fc00::/7
        if ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and $bytes[2] -eq 0x0D -and $bytes[3] -eq 0xB8) { return $false }
        return $true
    }
    return $false
}

function Get-GlobalIp {
    param(
        [string[]]$Urls,
        [ValidateSet('Any', 'IPv4', 'IPv6')][string]$ExpectedFamily = 'Any',
        [int]$TimeoutSec = 8
    )
    foreach ($u in $Urls) {
        try {
            $r = (Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop).Content.Trim()
            if ($r.Length -gt 64) { continue }
            $address = $null
            if (-not [System.Net.IPAddress]::TryParse($r, [ref]$address)) { continue }
            if (-not (Test-PublicInternetAddress -Address $address)) { continue }
            if ($ExpectedFamily -eq 'IPv4' -and $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }
            if ($ExpectedFamily -eq 'IPv6' -and $address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { continue }
            return $address.ToString()
        } catch { }
    }
    return $null
}

# ==========================================
# AS 情報（Team Cymru の DNS サービス）
# ==========================================
function ConvertTo-Ipv6Nibbles {
    # 2405:6582::1 → "1.0.0.0....5.0.4.2"（逆順ニブル）。origin6 の照会に使う
    param([string]$Ip)
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
        if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return $null }
        $bytes = $addr.GetAddressBytes()
        $nibbles = @()
        foreach ($b in $bytes) {
            $nibbles += ('{0:x}' -f ($b -shr 4))
            $nibbles += ('{0:x}' -f ($b -band 0x0F))
        }
        [array]::Reverse($nibbles)
        return ($nibbles -join '.')
    } catch { return $null }
}

function Get-AsnInfo {
    # IP → AS番号 / プレフィックス / 国 / レジストリ
    param([string]$Ip)
    if (-not $Ip) { return $null }
    try {
        $addr = [System.Net.IPAddress]::Parse($Ip)
    } catch { return $null }

    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $octets = $Ip.Split('.')
        [array]::Reverse($octets)
        $query = ($octets -join '.') + '.origin.asn.cymru.com'
    } else {
        $nib = ConvertTo-Ipv6Nibbles -Ip $Ip
        if (-not $nib) { return $null }
        $query = "$nib.origin6.asn.cymru.com"
    }

    try {
        $txt = @((Resolve-DnsName -Type TXT -Name $query -QuickTimeout -DnsOnly -ErrorAction Stop).Strings)
        if ($txt.Count -eq 0) { return $null }
        # 形式: "4685 | 138.64.0.0/16 | JP | apnic | 1995-08-30"
        # 複数プレフィックスが返ることがあるので、最も狭い（数字の大きい）ものを採る
        $best = $null
        foreach ($line in @($txt)) {
            $p = @($line -split '\|' | ForEach-Object { $_.Trim() })
            if ($p.Count -lt 3) { continue }
            $plen = 0
            if ($p[1] -match '/(\d+)$') { $plen = [int]$Matches[1] }
            if (-not $best -or $plen -gt $best.prefixLength) {
                $best = @{
                    asn          = ($p[0] -split '\s+')[0]
                    prefix       = $p[1]
                    prefixLength = $plen
                    country      = $p[2]
                    registry     = if ($p.Count -gt 3) { $p[3] } else { $null }
                    allocated    = if ($p.Count -gt 4) { $p[4] } else { $null }
                }
            }
        }
        if (-not $best) { return $null }

        # AS 番号 → 事業者名
        $asName = $null
        try {
            # .Strings は 1 件のときスカラの文字列を返す。@() で包まないと
            # [0] が「文字列の先頭 1 文字」になってしまう
            $asTxt = @((Resolve-DnsName -Type TXT -Name "AS$($best.asn).asn.cymru.com" -QuickTimeout -DnsOnly -ErrorAction Stop).Strings)
            if ($asTxt.Count -gt 0) {
                $ap = @([string]$asTxt[0] -split '\|' | ForEach-Object { $_.Trim() })
                if ($ap.Count -ge 5) { $asName = $ap[4] }
            }
        } catch { }

        return [PSCustomObject]@{
            asn       = $best.asn
            asName    = $asName
            prefix    = $best.prefix
            country   = $best.country
            registry  = $best.registry
            allocated = $best.allocated
        }
    } catch { return $null }
}

function Get-RdapInfo {
    # 割り当て名・組織名の裏取り（Cymru より詳しい名前が出ることがある）
    param([string]$Ip, [int]$TimeoutSec = 8)
    if (-not $Ip) { return $null }
    try { $parsedIp = [System.Net.IPAddress]::Parse($Ip) } catch { return $null }
    try {
        # RDAP.org はレジストリを自動選択する用途のブートストラップサービス。
        $r = Invoke-RestMethod -Uri "https://rdap.org/ip/$($parsedIp.ToString())" -TimeoutSec $TimeoutSec -ErrorAction Stop
        $orgNames = @()
        foreach ($e in @($r.entities)) {
            try {
                foreach ($v in @($e.vcardArray[1])) {
                    if ($v[0] -eq 'fn' -and $v[3]) { $orgNames += [string]$v[3] }
                }
            } catch { }
        }
        return [PSCustomObject]@{
            name          = [string]$r.name
            handle        = [string]$r.handle
            country       = [string]$r.country
            startAddress  = [string]$r.startAddress
            endAddress    = [string]$r.endAddress
            type          = [string]$r.type
            organizations = @($orgNames | Sort-Object -Unique)
        }
    } catch { return $null }
}

function Get-PtrName {
    param([string]$Ip)
    if (-not $Ip) { return $null }
    try {
        # 逆引きが引けないアドレスで待たされないよう QuickTimeout を付ける
        $p = @(Resolve-DnsName -Type PTR -Name $Ip -QuickTimeout -DnsOnly -ErrorAction Stop | Where-Object { $_.NameHost })
        if ($p.Count -gt 0) { return [string]$p[0].NameHost }
    } catch { }
    return $null
}

# ==========================================
# 接続方式の推定
#   逆引きホスト名には事業者の接続方式がほぼそのまま出る。
#   国内の主要な IPoE / IPv4 over IPv6 サービスのパターンを並べている。
# ==========================================
function Get-AccessMethod {
    param([string]$Ptr, [bool]$HasGlobalV6, [bool]$V6Preferred, $WanInfo, [string]$GlobalV4)

    $method = $null; $service = $null; $evidence = @()
    $p = if ($Ptr) { $Ptr.ToLower() } else { '' }

    if ($p) {
        $evidence += "逆引き: $Ptr"
        switch -Regex ($p) {
            # 方式の対応: v6プラス/OCN VC = MAP-E、transix/クロスパス/v6コネクト = DS-Lite。
            # MAP-E は限られたポートで開放可、DS-Lite は不可 — この違いが案内に効くため取り違えない
            'v6connect\.net'                 { $method = 'IPv4 over IPv6 (DS-Lite)'; $service = 'v6コネクト'; break }
            'xpass\.jp|cross-?pass'          { $method = 'IPv4 over IPv6 (DS-Lite)'; $service = 'クロスパス'; break }
            'v6plus|enabler\.ne\.jp'         { $method = 'IPv4 over IPv6 (MAP-E)'; $service = 'v6プラス (JPNE)'; break }
            'vc\.ocn\.ne\.jp|ocn.*virtual'   { $method = 'IPv4 over IPv6 (MAP-E)'; $service = 'OCNバーチャルコネクト'; break }
            'ocn\.ne\.jp'                    { $method = 'PPPoE'; $service = 'OCN'; break }
            'transix'                        { $method = 'IPv4 over IPv6 (DS-Lite)'; $service = 'transix'; break }
            'nuro\.jp'                       { $method = 'ネイティブ接続'; $service = 'NURO 光'; break }
            '\.zaq\.ne\.jp|jcom'             { $method = 'ケーブルテレビ回線'; $service = 'J:COM'; break }
            'commufa\.jp'                    { $method = 'ネイティブ接続'; $service = 'コミュファ光'; break }
            'eonet\.ne\.jp'                  { $method = 'ネイティブ接続'; $service = 'eo光'; break }
            'infoweb\.ne\.jp'                { $method = 'PPPoE'; $service = '@nifty'; break }
            'mesh\.ad\.jp'                   { $method = 'PPPoE'; $service = 'BIGLOBE'; break }
            'plala\.or\.jp'                  { $method = 'PPPoE'; $service = 'ぷらら'; break }
            'so-net\.ne\.jp'                 { $method = 'PPPoE'; $service = 'So-net'; break }
            'ppp|pppoe'                      { $method = 'PPPoE'; $service = $null; break }
            'bbtec\.net'                     { $method = 'IPoE'; $service = 'SoftBank 光'; break }
            'spmode\.ne\.jp|docomo'          { $method = 'モバイル回線'; $service = 'docomo'; break }
            # au-net はモバイルと au ひかりの両方で使われるため回線種別は断定しない
            'au-net\.ne\.jp|kddi'            { $method = 'KDDI回線'; $service = 'au'; break }
            'rakuten'                        { $method = 'モバイル回線'; $service = '楽天モバイル'; break }
            'ipv6|ipoe'                      { $method = 'IPoE'; $service = $null; break }
        }
    }

    # ルータの WAN 側 IPv4 と、外から見える IPv4 が違う＝共有IP(CGN/MAP-E)
    if ($WanInfo -and $GlobalV4) {
        if ($WanInfo.externalIp -and $WanInfo.externalIp -ne $GlobalV4) {
            $evidence += "ルータのWAN側IP($($WanInfo.externalIp))と外部から見えるIP($GlobalV4)が異なる → 事業者側で共有(CGN/MAP-E)"
            if (-not $method) { $method = 'IPv4 共有 (CGN / MAP-E)' }
        } elseif (-not $WanInfo.externalIp -and "$($WanInfo.connectionStatus)" -ne 'Connected') {
            $evidence += "ルータのWAN側はIPv4未接続だが外部通信は可能 → IPv4 over IPv6 の可能性"
            if (-not $method) { $method = 'IPv4 over IPv6' }
        }
    }

    if ($HasGlobalV6) { $evidence += "グローバル IPv6 あり（IPoE 利用可）" }
    if ($V6Preferred) { $evidence += "デュアルスタック環境で IPv6 が優先されている" }

    if (-not $method) {
        $method = if ($HasGlobalV6) { 'IPoE（詳細不明）' } else { '不明' }
    }
    return [PSCustomObject]@{ method = $method; service = $service; evidence = @($evidence) }
}

# ==========================================
# STUN による外側アドレス観測 (RFC 5389)
#   1 台の STUN サーバへの Binding Request だけでは NAT の型までは確定できない。
#   外側から見える IP:Port の観測値として表示し、Cone/Symmetric とは断定しない。
# ==========================================
$script:StunMagicCookie = [byte[]]@(0x21, 0x12, 0xA4, 0x42)

function New-StunBindingRequest {
    # Binding Request: type=0x0001, length=0, magic cookie, 96bit transaction id
    param([byte[]]$TransactionId)
    $buf = New-Object System.Collections.Generic.List[byte]
    $buf.AddRange([byte[]]@(0x00, 0x01))   # Message Type: Binding Request
    $buf.AddRange([byte[]]@(0x00, 0x00))   # Message Length: 属性なし
    $buf.AddRange($script:StunMagicCookie)
    $buf.AddRange($TransactionId)
    return $buf.ToArray()
}

function Read-StunMappedAddress {
    # 応答から自分の外側アドレス(IP:Port)を取り出す。
    # XOR-MAPPED-ADDRESS(0x0020) を優先し、古い MAPPED-ADDRESS(0x0001) にも対応。
    param([byte[]]$Data)
    if ($null -eq $Data -or $Data.Length -lt 20) { return $null }
    # 重要: PowerShell の -shl は左辺の型幅でシフト量がマスクされる。
    # byte のまま 8 ビット左シフトすると値が変わらず、上位バイトが消える。
    # 2 バイト値を組み立てるときは必ず [int] にしてからシフトすること。
    $msgType = ([int]$Data[0] -shl 8) -bor [int]$Data[1]
    if ($msgType -ne 0x0101) { return $null }   # Binding Success Response 以外

    $len = ([int]$Data[2] -shl 8) -bor [int]$Data[3]
    $off = 20
    $end = [math]::Min(20 + $len, $Data.Length)
    $result = $null

    while ($off + 4 -le $end) {
        $attrType = ([int]$Data[$off] -shl 8) -bor [int]$Data[$off + 1]
        $attrLen  = ([int]$Data[$off + 2] -shl 8) -bor [int]$Data[$off + 3]
        $val = $off + 4
        if ($val + $attrLen -gt $Data.Length) { break }

        if (($attrType -eq 0x0020 -or $attrType -eq 0x0001) -and $attrLen -ge 8) {
            $family = $Data[$val + 1]
            if ($family -eq 0x01) {   # IPv4
                $port = ([int]$Data[$val + 2] -shl 8) -bor [int]$Data[$val + 3]
                $ipb  = @($Data[($val + 4)..($val + 7)])
                if ($attrType -eq 0x0020) {
                    # XOR されているので magic cookie で戻す
                    $port = $port -bxor 0x2112
                    $ipb = @(for ($i = 0; $i -lt 4; $i++) { $ipb[$i] -bxor $script:StunMagicCookie[$i] })
                }
                $addr = ($ipb -join '.')
                $cand = [PSCustomObject]@{ ip = $addr; port = $port }
                # XOR 版が取れたらそちらを優先
                if ($attrType -eq 0x0020) { return $cand }
                if (-not $result) { $result = $cand }
            }
        }
        # 属性は 4 バイト境界にパディングされる
        $off = $val + $attrLen
        if ($attrLen % 4 -ne 0) { $off += 4 - ($attrLen % 4) }
    }
    return $result
}

function Invoke-StunBinding {
    # 1 つの STUN サーバへ問い合わせ、外側から見えるアドレスを返す。
    param([string]$Server, [int]$Port = 3478, [int]$LocalPort = 0, [int]$TimeoutMs = 2500)
    $client = $null
    try {
        $rnd = New-Object byte[] 12
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($rnd) } finally { $rng.Dispose() }
        $req = New-StunBindingRequest -TransactionId $rnd

        $client = New-Object System.Net.Sockets.UdpClient($LocalPort)
        $client.Client.ReceiveTimeout = $TimeoutMs
        $actualLocalPort = ([System.Net.IPEndPoint]$client.Client.LocalEndPoint).Port

        [void]$client.Send($req, $req.Length, $Server, $Port)
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $resp = $client.Receive([ref]$remote)
        $mapped = Read-StunMappedAddress -Data $resp
        if (-not $mapped) { return $null }
        return [PSCustomObject]@{
            server     = "${Server}:${Port}"
            mappedIp   = $mapped.ip
            mappedPort = $mapped.port
            localPort  = $actualLocalPort
        }
    } catch {
        return $null
    } finally {
        if ($client) { try { $client.Close() } catch { } }
    }
}

function Get-NatType {
    <#
        Cloudflare が公開用途として案内している STUN エンドポイントへ 1 回問い合わせ、
        外側から見えるアドレスを返す。単一宛先の観測だけで NAT 型は断定しない。
    #>
    param([int]$TimeoutMs = 2500)
    $localPort = Get-Random -Minimum 50000 -Maximum 60000
    $result = Invoke-StunBinding -Server 'stun.cloudflare.com' -Port 3478 -LocalPort $localPort -TimeoutMs $TimeoutMs
    if (-not $result) {
        # 固定ポートが既に使われていた場合に備え、OS 選択ポートで 1 回だけ再試行する。
        $result = Invoke-StunBinding -Server 'stun.cloudflare.com' -Port 3478 -TimeoutMs $TimeoutMs
    }
    if (-not $result) {
        return [PSCustomObject]@{
            natType = '観測不可'
            detail  = 'Cloudflare STUN に到達できませんでした（UDP がブロックされている可能性）'
            mappedIp = $null; mappedPorts = @(); localPort = $localPort; observations = @()
        }
    }

    $portDetail = if ($result.mappedPort -eq $result.localPort) {
        "送信元と外側のポートは同じ $($result.localPort) でした"
    } else {
        "送信元ポート $($result.localPort) は外側で $($result.mappedPort) に変換されました"
    }

    return [PSCustomObject]@{
        natType      = 'STUN 応答あり（詳細型は未判定）'
        detail       = "$portDetail。単一の STUN 宛先による観測のため、Cone/Symmetric などの NAT 型や着信可否は判定していません"
        mappedIp     = $result.mappedIp
        mappedPorts  = @($result.mappedPort)
        localPort    = $result.localPort
        observations = @($result)
    }
}

# ==========================================
# 共有 IPv4（CGN / MAP-E）でのポート開放の可否
#   MAP-E や CGN ではグローバル IPv4 を他人と分け合っており、
#   使えるポートが限られる。任意のポート開放は原理的にできず、
#   UPnP のポートマッピングも通らない。ゲームのポート開放でハマる典型。
# ==========================================
function Get-PortForwardingCapability {
    param($AccessMethod, $NatInfo, $WanInfo, [string]$GlobalV4)

    $shared = $false
    $reasons = @()

    if ($AccessMethod -and "$($AccessMethod.method)" -match 'MAP-E|DS-Lite|CGN|共有') {
        $shared = $true
        $reasons += "接続方式が $($AccessMethod.method) のため、グローバル IPv4 を他の利用者と共有しています"
    }
    if ($WanInfo -and $WanInfo.externalIp -and $GlobalV4 -and $WanInfo.externalIp -ne $GlobalV4) {
        $shared = $true
        $reasons += "ルーターが持つ WAN 側 IP ($($WanInfo.externalIp)) と、外部から見える IP ($GlobalV4) が違います"
    }
    if ($shared) {
        # MAP-E では送信元ポートが割り当て範囲に書き換えられる。
        # 実際に観測されたポートを見せると「共有されている」ことが具体的に分かる
        if ($NatInfo -and @($NatInfo.mappedPorts).Count -gt 0 -and $NatInfo.localPort) {
            $obs = @($NatInfo.mappedPorts) -join ', '
            if (@($NatInfo.mappedPorts) -notcontains $NatInfo.localPort) {
                $reasons += "送信元ポート $($NatInfo.localPort) が、外側では $obs に書き換えられていました（事業者が割り当てた範囲に押し込まれています）"
            }
        }
        return [PSCustomObject]@{
            canForwardArbitraryPorts = $false
            summary = 'ポート開放は原則できません（IPv4 共有環境）'
            reasons = @($reasons)
            advice  = @(
                'ルーターのポート開放設定を行っても、割り当て外のポートは外部から届きません（UPnP も同様に失敗します）'
                '外部公開やポート開放が必要なら、PPPoE 接続の併用、固定 IP オプション、または VPN や Cloudflare Tunnel のような外向き接続を使う方式を検討してください'
                'ゲーム機の NAT タイプ改善が目的なら、まず二重 NAT の解消と UPnP の有効化を確認してください'
            )
        }
    }
    return [PSCustomObject]@{
        canForwardArbitraryPorts = $null
        summary = 'ポート開放の可否は未確認です'
        reasons = @($reasons)
        advice  = @('外部からの着信テストは行っていません。必要な場合は、ルーターの WAN 側 IPv4 と外部から見える IPv4 の一致、ファイアウォール、契約条件を確認してください')
    }
}

# ==========================================
# Main
# ==========================================
Write-Host "=========================================" -ForegroundColor Magenta
Write-Host " Network Topology Mapper - Internet Info" -ForegroundColor Magenta
Write-Host "=========================================" -ForegroundColor Magenta

Write-Step "グローバル IP を確認中..."
$v4 = Get-GlobalIp -TimeoutSec $TimeoutSec -ExpectedFamily IPv4 -Urls @('https://api.ipify.org')
# api64 は IPv6 が使えるなら IPv6 を返す。これで「どちらが優先されているか」も分かる
$auto = Get-GlobalIp -TimeoutSec $TimeoutSec -ExpectedFamily Any -Urls @('https://api64.ipify.org')
$v6 = Get-GlobalIp -TimeoutSec $TimeoutSec -ExpectedFamily IPv6 -Urls @('https://api6.ipify.org')
$v6Preferred = ($auto -and $auto -match ':')

if ($v4) { Write-Ok "グローバル IPv4: $v4" } else { Write-Warn2 "グローバル IPv4 を取得できませんでした" }

# 「IPv6 アドレスを持っている」ことと「IPv6 で外に出られる」ことは別問題。
# アドレスはあるのに外部に出られない（上流未開通/ルータ設定）ケースを区別する。
$localGua = $null
if (Test-Path $InputPath) {
    try {
        $ndEarly = Get-Content $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($a in @($ndEarly.adapters)) {
            foreach ($ip6 in @($a.ipv6Addresses)) {
                if ($ip6.scope -eq 'global') { $localGua = [string]$ip6.address; break }
            }
            if ($localGua) { break }
        }
    } catch { }
}

if ($v6) {
    Write-Ok "グローバル IPv6: $v6"
} elseif ($localGua) {
    Write-Warn2 "IPv6 アドレス($localGua)は持っていますが、IPv6 で外部に到達できませんでした（上流未開通/経路の問題の可能性）"
} else {
    Write-Warn2 "グローバル IPv6 なし（IPv4 のみ）"
}

Write-Step "逆引きとプロバイダ情報を照会中..."
$ptr4 = Get-PtrName -Ip $v4
$ptr6 = Get-PtrName -Ip $v6
$asn4 = Get-AsnInfo -Ip $v4
$asn6 = Get-AsnInfo -Ip $v6
if ($asn4) { Write-Ok "プロバイダ: $($asn4.asName) (AS$($asn4.asn)) / $($asn4.prefix)" }
if ($ptr4) { Write-Ok "逆引き: $ptr4" }

$rdap = $null
if (-not $SkipRdap -and $v4) {
    Write-Step "RDAP で割り当て情報を照会中..."
    $rdap = Get-RdapInfo -Ip $v4 -TimeoutSec $TimeoutSec
    if ($rdap) { Write-Ok "割り当て: $($rdap.name) [$($rdap.startAddress) - $($rdap.endAddress)]" }
}

# 収集済みデータから UPnP の WAN 情報と traceroute を再利用する
$wanInfo = $null
$traceHops = @()
if (Test-Path $InputPath) {
    try {
        $nd = Get-Content $InputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($nd.wanInfo) { $wanInfo = $nd.wanInfo }
        if ($nd.traceroute -and $nd.traceroute.hops) { $traceHops = @($nd.traceroute.hops) }
    } catch { }
}

$access = Get-AccessMethod -Ptr $ptr4 -HasGlobalV6 ([bool]$v6) -V6Preferred $v6Preferred -WanInfo $wanInfo -GlobalV4 $v4
Write-Ok "接続方式の推定: $($access.method)$(if ($access.service) { " [$($access.service)]" })"

$nat = $null
if (-not $SkipNat) {
    Write-Step "外側から見えるアドレスを確認中（STUN）..."
    $nat = Get-NatType -TimeoutMs ($TimeoutSec * 1000)
    Write-Ok "STUN: $($nat.natType)$(if ($nat.mappedIp) { " (外側 $($nat.mappedIp):$(@($nat.mappedPorts) -join ','))" })"
}

$portFwd = Get-PortForwardingCapability -AccessMethod $access -NatInfo $nat -WanInfo $wanInfo -GlobalV4 $v4
if ($true -eq $portFwd.canForwardArbitraryPorts) {
    Write-Ok $portFwd.summary
} elseif ($false -eq $portFwd.canForwardArbitraryPorts) {
    Write-Warn2 $portFwd.summary
} else {
    Write-Host "[~] $($portFwd.summary)" -ForegroundColor DarkGray
}

# traceroute の各ホップがどの事業者を通っているか
$asPath = @()
if ($traceHops.Count -gt 0) {
    Write-Step "経路上の事業者(AS)を照会中..."
    $seenAsn = [ordered]@{}
    foreach ($h in $traceHops) {
        # Collect-NetworkInfo.ps1 のホップは ipAddress。ホスト名は持たないのでここで逆引きする
        $hip = [string]$h.ipAddress
        if (-not $hip -or $hip -eq '*') { continue }
        # プライベートアドレスは宅内なので外部照会しない
        if ($hip -match '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.)') {
            $asPath += [PSCustomObject]@{ hop = $h.hop; address = $hip; hostname = $null; rtt = $h.avgRtt; asn = $null; asName = '宅内' }
            continue
        }
        $ha = Get-AsnInfo -Ip $hip
        $asPath += [PSCustomObject]@{
            hop      = $h.hop
            address  = $hip
            hostname = (Get-PtrName -Ip $hip)
            rtt      = $h.avgRtt
            asn      = if ($ha) { $ha.asn } else { $null }
            asName   = if ($ha) { $ha.asName } else { $null }
        }
        if ($ha -and $ha.asn -and -not $seenAsn.Contains($ha.asn)) { $seenAsn[$ha.asn] = $ha.asName }
    }
    $pathText = @($seenAsn.Values | Where-Object { $_ }) -join ' → '
    if ($pathText) { Write-Ok "経路上の事業者: $pathText" }
}

$result = [PSCustomObject]@{
    fetchedAt     = (Get-Date).ToString("o")
    globalIPv4    = $v4
    globalIPv6    = $v6
    localGlobalIPv6 = $localGua
    ipv6Preferred = $v6Preferred
    reverseIPv4   = $ptr4
    reverseIPv6   = $ptr6
    ispIPv4       = $asn4
    ispIPv6       = $asn6
    rdap          = $rdap
    accessMethod  = $access
    nat           = $nat
    portForwarding = $portFwd
    # 旧 JSON 利用側との互換用。非公開 DNS whoami サービスへの照会は廃止した。
    dnsResolvers  = @()
    asPath        = @($asPath)
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$result | ConvertTo-Json -Depth 8 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Ok "保存: $OutputPath"
