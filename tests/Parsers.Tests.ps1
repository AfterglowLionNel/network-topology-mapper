<#
    日本語版/英語版 Windows のコマンド出力パーサと、
    ネットワーク計算まわりの回帰テスト。

    実行方法: .\tests\Invoke-Tests.ps1
#>

BeforeAll {
    $repoRoot   = Split-Path -Parent $PSScriptRoot
    $scriptsDir = Join-Path $repoRoot 'scripts'
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'Find-DeviceInfo.ps1') -Name @(
        'ConvertFrom-NbtstatOutput', 'Read-DnsName', 'Read-DnsRecords', 'New-MdnsQuery',
        'Get-MdnsServiceType', 'Get-MdnsInstanceLabel', 'Get-DeviceTypeGuess', 'Get-OuiVendor',
        'Test-SafeLocalHttpUri', 'ConvertFrom-SafeXml', 'Test-Ipv4InCidr',
        'Test-IpInAllowedCidrs', 'Test-PrivateIpv4Address'
    ))))

    . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'Run-NetworkMapper.ps1') -Name @(
        'Get-Ipv4ScanRange', 'Test-DisallowedAdapterName', 'Get-SafeScanTargets'
    ))))

    . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'Test-NetworkHealth.ps1') -Name @(
        'ConvertFrom-NetshWlanInterfaces', 'ConvertTo-NumberOrNull', 'Convert-SpeedTextToMbps',
        'Start-ParallelWorkers', 'Wait-ParallelWorkers', 'Invoke-ParallelWorkers',
        'Get-ChannelRecommendation'
    ))))

    function New-Ap {
        param([int]$Ch, [int]$Signal = 80)
        [PSCustomObject]@{ chNum = $Ch; signalPercent = $Signal; ssid = "ap$Ch"; bssid = "00:00:00:00:00:0$Ch" }
    }

    . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'New-NetworkDiagram.ps1') -Name @(
        'Get-NetworkCidr', 'Test-IpInSubnet', 'Test-SkipNeighbor', 'Get-LinkStyleSpec',
        'Get-SignalColorFromPct', 'Get-Median', 'Format-MermaidLabel', 'Get-NodeId', 'Get-NormMac2',
        'Get-NetworkIdentity', 'ConvertTo-SafeJavaScriptJson', 'Get-SafeHexColor',
        'Get-SafeMermaidDash', 'Get-SafeStrokeWidth', 'Protect-CsvCell',
        'Reset-PublicRedactionState', 'Add-PublicExactReplacement', 'Get-PublicIpv4',
        'Get-PublicIpv6', 'Get-PublicMac', 'Protect-PublicText',
        'Initialize-PublicRedaction', 'ConvertTo-PublicSafeObject',
        'ConvertTo-AiPromptPlainText', 'ConvertTo-AiPromptMetricText', 'New-AiRepairPrompt'
    ))))

    . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'Repair-NetworkSetting.ps1') -Name @(
        'Test-SafeActionText', 'Test-RepairAction', 'Get-Sha256Hex', 'Read-ValidatedRepairPlan'
    ))))

    # Get-NetworkIdentity のテスト用の最小データ
    function New-NetData {
        param([string]$GwIp = '192.168.1.1', [string]$GwMac = 'AA-BB-CC-DD-EE-FF',
              [string]$Ssid = $null, [switch]$WiredPath)
        $adapterName = if ($WiredPath) { 'イーサネット' } else { 'Wi-Fi' }
        $media       = if ($WiredPath) { '802.3' } else { '802.11' }
        [PSCustomObject]@{
            adapters = @([PSCustomObject]@{
                name = $adapterName; description = $adapterName; mediaType = $media; ipv4Gateway = $GwIp
            })
            routes = @([PSCustomObject]@{ destinationPrefix = '0.0.0.0/0'; nextHop = $GwIp })
            neighbors = @([PSCustomObject]@{ ipAddress = $GwIp; macAddress = $GwMac })
            wifi = if ($Ssid) { [PSCustomObject]@{ ssid = $Ssid } } else { $null }
        }
    }
}

Describe '型付き修復操作の検証' {
    It '許可した操作と値だけを受け入れる' {
        Test-RepairAction ([PSCustomObject]@{ type = 'TcpAutoTuning'; level = 'normal' }) | Should -BeTrue
        Test-RepairAction ([PSCustomObject]@{ type = 'TcpRss'; state = 'enabled' }) | Should -BeTrue
        Test-RepairAction ([PSCustomObject]@{ type = 'AdapterBinding'; adapterName = "LAN's adapter"; componentId = 'ms_tcpip6'; enabled = $true }) | Should -BeTrue
        Test-RepairAction ([PSCustomObject]@{ type = 'DnsSet'; adapterName = 'Ethernet'; addresses = @('1.1.1.1', '8.8.8.8') }) | Should -BeTrue
        Test-RepairAction ([PSCustomObject]@{ type = 'InterfaceMetric'; adapterName = 'Ethernet'; mode = 'Manual'; metric = 9999 }) | Should -BeTrue
    }

    It '任意コマンド・不正値・制御文字を拒否する' {
        Test-RepairAction ([PSCustomObject]@{ type = 'RunCommand'; command = 'Remove-Item C:\' }) | Should -BeFalse
        Test-RepairAction ([PSCustomObject]@{ type = 'TcpAutoTuning'; level = 'normal & whoami' }) | Should -BeFalse
        Test-RepairAction ([PSCustomObject]@{ type = 'AdapterBinding'; adapterName = "LAN`nInjected"; componentId = 'ms_tcpip6'; enabled = $true }) | Should -BeFalse
        Test-RepairAction ([PSCustomObject]@{ type = 'DnsSet'; adapterName = 'Ethernet'; addresses = @('not-an-ip') }) | Should -BeFalse
        Test-RepairAction ([PSCustomObject]@{ type = 'InterfaceMetric'; adapterName = 'Ethernet'; mode = 'Manual'; metric = 10000 }) | Should -BeFalse
        Test-RepairAction ([PSCustomObject]@{ type = 'AdapterAdvancedRegistry'; adapterName = 'Ethernet'; registryKeyword = '*Other'; registryValue = 512 }) | Should -BeFalse
    }

    It '同じバイト列から決定論的な SHA-256 を得る' {
        $bytes = [Text.Encoding]::UTF8.GetBytes('repair-plan')
        Get-Sha256Hex -Bytes $bytes | Should -Be '49BD577CA83B5C7DD9FEA534950272497B6482AE3B1BCD33C9CE6D6D378CBE2E'
    }

    It '昇格用プランの改ざんと所定フォルダ外のファイルを拒否する' {
        $planDir = Join-Path ([IO.Path]::GetTempPath()) 'NetworkTopologyMapper\repair-plans'
        [void][IO.Directory]::CreateDirectory($planDir)
        $planPath = Join-Path $planDir ("pester-$([guid]::NewGuid().ToString('N')).json")
        $outsidePath = Join-Path ([IO.Path]::GetTempPath()) ("pester-repair-outside-$([guid]::NewGuid().ToString('N')).json")
        $plan = [PSCustomObject]@{
            schemaVersion = 1
            purpose = 'Apply'
            actions = @([PSCustomObject]@{ type = 'TcpRss'; state = 'enabled' })
        } | ConvertTo-Json -Depth 5
        try {
            [IO.File]::WriteAllText($planPath, $plan, [Text.UTF8Encoding]::new($true))
            $bytes = [IO.File]::ReadAllBytes($planPath)
            $hash = Get-Sha256Hex -Bytes $bytes
            (Read-ValidatedRepairPlan -Path $planPath -ExpectedHash $hash).purpose | Should -Be 'Apply'

            [IO.File]::AppendAllText($planPath, ' ')
            { Read-ValidatedRepairPlan -Path $planPath -ExpectedHash $hash } | Should -Throw

            [IO.File]::WriteAllText($outsidePath, $plan, [Text.UTF8Encoding]::new($true))
            $outsideHash = Get-Sha256Hex -Bytes ([IO.File]::ReadAllBytes($outsidePath))
            { Read-ValidatedRepairPlan -Path $outsidePath -ExpectedHash $outsideHash } | Should -Throw
        } finally {
            if ([IO.File]::Exists($planPath)) { [IO.File]::Delete($planPath) }
            if ([IO.File]::Exists($outsidePath)) { [IO.File]::Delete($outsidePath) }
        }
    }

    It '修復スクリプトに文字列コマンド実行を残さない' {
        $source = Get-Content (Join-Path $scriptsDir 'Repair-NetworkSetting.ps1') -Raw -Encoding UTF8
        $source | Should -Not -Match 'Invoke-Expression'
        $source | Should -Not -Match 'rollbackCommand'
        $source | Should -Not -Match 'appliedCommand'
    }
}

Describe 'LAN 内 HTTP 取得先の検証' {
    It '応答元と同じ IPv4 アドレスだけを許可する' {
        Test-SafeLocalHttpUri -Uri 'http://192.168.1.1:8080/device.xml' -ExpectedIp '192.168.1.1' | Should -BeTrue
        Test-SafeLocalHttpUri -Uri 'http://192.168.1.2/device.xml' -ExpectedIp '192.168.1.1' | Should -BeFalse
    }

    It '同じ IPv6 アドレスを角括弧付き URL でも許可する' {
        Test-SafeLocalHttpUri -Uri 'http://[fd00::1]:8080/device.xml' -ExpectedIp 'fd00::1' | Should -BeTrue
    }

    It 'ホスト名・認証情報・フラグメント・非 HTTP スキームを拒否する' {
        Test-SafeLocalHttpUri -Uri 'http://router.local/device.xml' -ExpectedIp '192.168.1.1' | Should -BeFalse
        Test-SafeLocalHttpUri -Uri 'http://user:pass@192.168.1.1/device.xml' -ExpectedIp '192.168.1.1' | Should -BeFalse
        Test-SafeLocalHttpUri -Uri 'http://192.168.1.1/device.xml#part' -ExpectedIp '192.168.1.1' | Should -BeFalse
        Test-SafeLocalHttpUri -Uri 'file:///C:/Windows/win.ini' -ExpectedIp '192.168.1.1' | Should -BeFalse
    }
}

Describe '安全な XML 読み込み' {
    It '通常の XML を読み込める' {
        $xml = ConvertFrom-SafeXml -Text '<root><name>router</name></root>'
        $xml.root.name | Should -Be 'router'
    }

    It 'DTD を含む XML を拒否する' {
        { ConvertFrom-SafeXml -Text '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>' } |
            Should -Throw
    }
}

Describe 'nbtstat 出力の解釈' {
    It '英語版の出力からコンピュータ名・ワークグループ・MAC を取り出す' {
        $out = @'

Local Area Connection:
Node IpAddress: [192.168.1.10] Scope Id: []

           NetBIOS Remote Machine Name Table

       Name               Type         Status
    ---------------------------------------------
    DESKTOP-ABC    <00>  UNIQUE      Registered
    WORKGROUP      <00>  GROUP       Registered
    DESKTOP-ABC    <20>  UNIQUE      Registered

    MAC Address = 00-00-5E-00-53-03

'@
        $r = ConvertFrom-NbtstatOutput -Output $out
        $r.name      | Should -Be 'DESKTOP-ABC'
        $r.workgroup | Should -Be 'WORKGROUP'
        $r.mac       | Should -Be '00-00-5E-00-53-03'
    }

    It '日本語版の出力（一意/グループ）も同じように解釈する' {
        $out = @'

イーサネット:
ノード IpAddress: [192.168.1.10] スコープ ID: []

           NetBIOS リモート コンピュータ名テーブル

       名前               種類         状態
    ---------------------------------------------
    NAS-01         <00>  一意        登録済み
    WORKGROUP      <00>  グループ    登録済み

    MAC アドレス = AA-BB-CC-DD-EE-FF

'@
        $r = ConvertFrom-NbtstatOutput -Output $out
        $r.name      | Should -Be 'NAS-01'
        $r.workgroup | Should -Be 'WORKGROUP'
        $r.mac       | Should -Be 'AA-BB-CC-DD-EE-FF'
    }

    It '応答が無い相手には null を返す' {
        ConvertFrom-NbtstatOutput -Output 'Host not found.' | Should -BeNullOrEmpty
        ConvertFrom-NbtstatOutput -Output 'ホストが見つかりません。' | Should -BeNullOrEmpty
        ConvertFrom-NbtstatOutput -Output '' | Should -BeNullOrEmpty
    }

    It '名前テーブルが無い出力では null を返す' {
        ConvertFrom-NbtstatOutput -Output "何かのゴミ出力`n複数行" | Should -BeNullOrEmpty
    }
}

Describe 'netsh wlan show interfaces の解釈' {
    It '英語版の出力を解釈する' {
        $lines = @(
            '    Name                   : Wi-Fi'
            '    State                  : connected'
            '    SSID                   : MyHome-5G'
            '    BSSID                  : aa:bb:cc:dd:ee:ff'
            '    Radio type             : 802.11ax'
            '    Authentication         : WPA2-Personal'
            '    Band                   : 5 GHz'
            '    Channel                : 44'
            '    Receive rate (Mbps)    : 866.7'
            '    Transmit rate (Mbps)   : 866.7'
            '    Signal                 : 87%'
        )
        $r = ConvertFrom-NetshWlanInterfaces -Lines $lines
        $r.ssid             | Should -Be 'MyHome-5G'
        $r.connected        | Should -BeTrue
        $r.band             | Should -Be '5 GHz'
        $r.channel          | Should -Be '44'
        $r.signalPercent    | Should -Be 87
        $r.receiveRateMbps  | Should -Be 866.7
        $r.transmitRateMbps | Should -Be 866.7
    }

    It '日本語版の出力を解釈する' {
        $lines = @(
            '    名前                   : Wi-Fi'
            '    状態                   : 接続されました'
            '    SSID                   : わが家-6G'
            '    BSSID                  : aa:bb:cc:dd:ee:00'
            '    無線の種類             : 802.11be'
            '    認証                   : WPA3-Personal'
            '    帯域                   : 6 GHz'
            '    チャネル               : 37'
            '    受信速度 (Mbps)        : 1441'
            '    送信速度 (Mbps)        : 1441'
            '    シグナル               : 92%'
        )
        $r = ConvertFrom-NetshWlanInterfaces -Lines $lines
        $r.ssid            | Should -Be 'わが家-6G'
        $r.connected       | Should -BeTrue
        $r.band            | Should -Be '6 GHz'
        $r.channel         | Should -Be '37'
        $r.signalPercent   | Should -Be 92
        $r.receiveRateMbps | Should -Be 1441
    }

    It 'SSID 行と BSSID 行を取り違えない' {
        $lines = @(
            '    SSID                   : Home'
            '    BSSID                  : 11:22:33:44:55:66'
        )
        $r = ConvertFrom-NetshWlanInterfaces -Lines $lines
        $r.ssid  | Should -Be 'Home'
        $r.bssid | Should -Be '11:22:33:44:55:66'
    }

    It '未接続（SSID なし）では null を返す' {
        ConvertFrom-NetshWlanInterfaces -Lines @('    状態                   : 切断されました') | Should -BeNullOrEmpty
        ConvertFrom-NetshWlanInterfaces -Lines @() | Should -BeNullOrEmpty
    }
}

Describe 'リンク速度テキストの換算' {
    It '<Text> は <Expected> Mbps' -ForEach @(
        @{ Text = '1 Gbps';               Expected = 1000 }
        @{ Text = '2.5 Gbps';             Expected = 2500 }
        @{ Text = '100 Mbps';             Expected = 100 }
        @{ Text = '1.0 Gbps Full Duplex'; Expected = 1000 }
        @{ Text = '10 Gbps';              Expected = 10000 }
    ) {
        Convert-SpeedTextToMbps -Text $Text | Should -Be $Expected
    }

    It '数値が無いテキストは null' {
        Convert-SpeedTextToMbps -Text 'Auto Negotiation' | Should -BeNullOrEmpty
        Convert-SpeedTextToMbps -Text 'オートネゴシエーション' | Should -BeNullOrEmpty
        Convert-SpeedTextToMbps -Text '' | Should -BeNullOrEmpty
    }
}

Describe 'mDNS パケットの解釈' {
    It 'A / PTR / TXT を取り出せる' {
        $packet = New-DnsTestPacket -Records @(
            @{ type = 1;  name = 'Kitchen-Speaker.local';        value = '192.168.1.50' }
            @{ type = 12; name = '_googlecast._tcp.local';        value = 'Kitchen._googlecast._tcp.local' }
            @{ type = 16; name = 'Kitchen._googlecast._tcp.local'; value = @('md=Chromecast Ultra', 'fn=Kitchen Speaker') }
        )
        $recs = Read-DnsRecords -Data $packet
        $recs.Count | Should -Be 3

        $a = @($recs | Where-Object { $_.type -eq 1 })[0]
        $a.name  | Should -Be 'Kitchen-Speaker.local'
        $a.value | Should -Be '192.168.1.50'

        $ptr = @($recs | Where-Object { $_.type -eq 12 })[0]
        $ptr.value | Should -Be 'Kitchen._googlecast._tcp.local'

        $txt = @($recs | Where-Object { $_.type -eq 16 })[0]
        @($txt.value) | Should -Contain 'md=Chromecast Ultra'
    }

    It '名前の圧縮ポインタ(0xC0)をたどれる' {
        # PTR の rdata を読むときにオフセットを二重に進めると、
        # 後続レコードを取りこぼす（過去に踏んだ不具合の回帰テスト）
        $packet = New-DnsTestPacket -CompressLastName -Records @(
            @{ type = 1;  name = 'AppleTV.local';         value = '192.168.1.60' }
            @{ type = 12; name = '_airplay._tcp.local';   value = 'Living._airplay._tcp.local' }
            @{ type = 16; name = 'ignored-by-pointer';    value = @('model=AppleTV6,2') }
        )
        $recs = Read-DnsRecords -Data $packet
        $recs.Count | Should -Be 3
        $txt = @($recs | Where-Object { $_.type -eq 16 })[0]
        $txt.name    | Should -Be 'AppleTV.local'
        @($txt.value)[0] | Should -Be 'model=AppleTV6,2'
    }

    It '256 バイト以上のオフセットを指す圧縮ポインタを解決できる' {
        # PowerShell の -shl は byte だとシフト量が型幅でマスクされ、
        # ([byte]1 -shl 8) が 1 のままになる。オフセットが 255 を超えると
        # ポインタの上位バイトが消えて別の場所を読んでしまう（実際に踏んだ）
        $filler = @()
        for ($i = 0; $i -lt 12; $i++) {
            $filler += @{ type = 16; name = "pad$i.local"; value = @(('x' * 20)) }
        }
        $records = @(@{ type = 1; name = 'FarAway.local'; value = '192.168.9.9' }) + $filler +
                   @(@{ type = 16; name = 'pointer-target'; value = @('model=Deep') })
        $packet = New-DnsTestPacket -CompressLastName -Records $records
        $packet.Length | Should -BeGreaterThan 256   # 圧縮先が 255 の外にあること

        $recs = Read-DnsRecords -Data $packet
        $recs.Count | Should -Be $records.Count
        $last = $recs[-1]
        $last.name | Should -Be 'FarAway.local'
        @($last.value)[0] | Should -Be 'model=Deep'
    }

    It 'レコード数が 256 件以上でも読み切れる' {
        # ANCOUNT の上位バイトが落ちると 300 件が 44 件になる
        $records = @()
        for ($i = 0; $i -lt 300; $i++) { $records += @{ type = 1; name = "h$i.local"; value = '10.0.0.1' } }
        $recs = Read-DnsRecords -Data (New-DnsTestPacket -Records $records)
        $recs.Count | Should -Be 300
    }

    It '壊れた/短すぎるパケットで例外を投げない' {
        @(Read-DnsRecords -Data @()).Count | Should -Be 0
        @(Read-DnsRecords -Data ([byte[]]@(0, 1, 2))).Count | Should -Be 0
        # ヘッダはあるが本体が切れている
        @(Read-DnsRecords -Data ([byte[]]@(0,0, 0x84,0, 0,0, 0,5, 0,0, 0,0, 3))).Count | Should -Be 0
    }

    It 'クエリは質問数とヘッダが正しい' {
        $q = New-MdnsQuery -Names @('_ipp._tcp.local', '_googlecast._tcp.local')
        $q.Length | Should -BeGreaterThan 12
        (($q[4] -shl 8) -bor $q[5]) | Should -Be 2   # QDCOUNT
        (($q[6] -shl 8) -bor $q[7]) | Should -Be 0   # ANCOUNT
        # 末尾は QTYPE=PTR(12), QCLASS=IN+unicast(0x8001)
        $q[$q.Length - 4] | Should -Be 0
        $q[$q.Length - 3] | Should -Be 12
        $q[$q.Length - 2] | Should -Be 0x80
        $q[$q.Length - 1] | Should -Be 1
    }

    It 'サービス型とインスタンス名を切り出せる' {
        Get-MdnsServiceType   -Name 'Living Room._googlecast._tcp.local' | Should -Be '_googlecast._tcp'
        Get-MdnsInstanceLabel -Name 'Living Room._googlecast._tcp.local' | Should -Be 'Living Room'
        Get-MdnsServiceType   -Name 'Printer._ipp._tcp.local.'           | Should -Be '_ipp._tcp'
        Get-MdnsServiceType   -Name 'ただの名前'                          | Should -BeNullOrEmpty
    }
}

Describe '機器種別の推定' {
    It 'mDNS のサービス型から種別を決める' {
        Get-DeviceTypeGuess -Mdns @{ services = @('_ipp._tcp', '_http._tcp') }                | Should -Be 'printer'
        Get-DeviceTypeGuess -Mdns @{ services = @('_googlecast._tcp') }                       | Should -Be 'tv'
        Get-DeviceTypeGuess -Mdns @{ services = @('_airplay._tcp', '_raop._tcp') }            | Should -Be 'tv'
        Get-DeviceTypeGuess -Mdns @{ services = @('_companion-link._tcp') }                   | Should -Be 'apple'
        Get-DeviceTypeGuess -Mdns @{ services = @('_afpovertcp._tcp') }                       | Should -Be 'nas'
    }

    It 'iPhone は AirPlay と companion-link の両方を出すので apple と判定する' {
        Get-DeviceTypeGuess -Mdns @{ services = @('_airplay._tcp', '_companion-link._tcp') } | Should -Be 'apple'
    }

    It 'ゲートウェイは常に router' {
        Get-DeviceTypeGuess -IsGateway $true -Mdns @{ services = @('_ipp._tcp') } | Should -Be 'router'
    }

    It '手掛かりが無ければ unknown' {
        Get-DeviceTypeGuess | Should -Be 'unknown'
    }
}

Describe 'OUI の照合' {
    It '区切り文字の違いを吸収して引ける' {
        $db = @{ '0024A5' = 'BUFFALO INC.' }
        Get-OuiVendor -Mac '00-24-A5-11-22-33' -Db $db | Should -Be 'BUFFALO INC.'
        Get-OuiVendor -Mac '00:24:a5:11:22:33' -Db $db | Should -Be 'BUFFALO INC.'
        Get-OuiVendor -Mac '0024A5112233'      -Db $db | Should -Be 'BUFFALO INC.'
    }

    It '未登録・短すぎる MAC は null' {
        $db = @{ '0024A5' = 'BUFFALO INC.' }
        Get-OuiVendor -Mac 'FF-FF-FF-11-22-33' -Db $db | Should -BeNullOrEmpty
        Get-OuiVendor -Mac '00-24'             -Db $db | Should -BeNullOrEmpty
        Get-OuiVendor -Mac $null               -Db $db | Should -BeNullOrEmpty
    }
}

Describe 'サブネット計算' {
    It '<Ip>/<Prefix> のネットワークは <Expected>' -ForEach @(
        @{ Ip = '192.168.1.37';  Prefix = 24; Expected = '192.168.1.0/24' }
        @{ Ip = '192.168.10.5';  Prefix = 22; Expected = '192.168.8.0/22' }
        @{ Ip = '10.1.2.3';      Prefix = 8;  Expected = '10.0.0.0/8' }
        @{ Ip = '172.29.32.1';   Prefix = 20; Expected = '172.29.32.0/20' }
    ) {
        Get-NetworkCidr -Ip $Ip -Prefix $Prefix | Should -Be $Expected
    }

    It '所属判定が正しい' {
        Test-IpInSubnet -Ip '192.168.1.99' -Cidr '192.168.1.0/24' | Should -BeTrue
        Test-IpInSubnet -Ip '192.168.2.1'  -Cidr '192.168.1.0/24' | Should -BeFalse
        Test-IpInSubnet -Ip '192.168.11.7' -Cidr '192.168.8.0/22' | Should -BeTrue
        Test-IpInSubnet -Ip '192.168.12.7' -Cidr '192.168.8.0/22' | Should -BeFalse
        Test-IpInSubnet -Ip ''             -Cidr '192.168.1.0/24' | Should -BeFalse
        Test-IpInSubnet -Ip '192.168.1.1'  -Cidr 'こわれた値'      | Should -BeFalse
    }
}

Describe 'LAN 能動調査の許可範囲' {
    It 'RFC1918 アドレスだけをプライベートとして扱う' {
        Test-PrivateIpv4Address '10.20.30.40' | Should -BeTrue
        Test-PrivateIpv4Address '172.16.0.1' | Should -BeTrue
        Test-PrivateIpv4Address '172.31.255.254' | Should -BeTrue
        Test-PrivateIpv4Address '192.168.1.1' | Should -BeTrue
        Test-PrivateIpv4Address '172.32.0.1' | Should -BeFalse
        Test-PrivateIpv4Address '100.64.0.1' | Should -BeFalse
        Test-PrivateIpv4Address '8.8.8.8' | Should -BeFalse
    }

    It '許可 CIDR の内外を正しく判定する' {
        Test-Ipv4InCidr -IpAddress '192.168.8.1' -Cidr '192.168.8.0/22' | Should -BeTrue
        Test-Ipv4InCidr -IpAddress '192.168.11.254' -Cidr '192.168.8.0/22' | Should -BeTrue
        Test-Ipv4InCidr -IpAddress '192.168.12.1' -Cidr '192.168.8.0/22' | Should -BeFalse
        Test-IpInAllowedCidrs -IpAddress '10.0.2.3' -Cidrs @('192.168.1.0/24', '10.0.0.0/22') | Should -BeTrue
        Test-IpInAllowedCidrs -IpAddress '10.0.4.1' -Cidrs @('192.168.1.0/24', '10.0.0.0/22') | Should -BeFalse
    }

    It '範囲を /22～/30 と最大ホスト数へ正規化する' {
        $range = Get-Ipv4ScanRange -IpAddress '192.168.10.45' -PrefixLength 24
        $range.cidr | Should -Be '192.168.10.0/24'
        $range.hostCount | Should -Be 254
        Get-Ipv4ScanRange -IpAddress '192.168.10.45' -PrefixLength 21 | Should -BeNullOrEmpty
        Get-Ipv4ScanRange -IpAddress '203.0.113.5' -PrefixLength 24 | Should -BeNullOrEmpty
    }

    It 'VPN・仮想アダプタ名を除外する' {
        Test-DisallowedAdapterName -Name 'vEthernet (WSL)' -Description 'Hyper-V Virtual Ethernet Adapter' | Should -BeTrue
        Test-DisallowedAdapterName -Name 'Tailscale' -Description 'Tunnel' | Should -BeTrue
        Test-DisallowedAdapterName -Name 'イーサネット' -Description 'Intel Ethernet Controller' | Should -BeFalse
    }

    It 'Publicプロファイルは明示した場合だけ確認候補へ含める' {
        Mock Get-NetConnectionProfile {
            [PSCustomObject]@{ InterfaceIndex = 7; NetworkCategory = 'Public' }
        }
        Mock Get-NetAdapter {
            [PSCustomObject]@{
                Status = 'Up'; ifIndex = 7; Name = 'Ethernet';
                InterfaceDescription = 'Physical Ethernet'; HardwareInterface = $true
            }
        }
        Mock Get-NetIPAddress {
            [PSCustomObject]@{ SkipAsSource = $false; IPAddress = '192.168.50.20'; PrefixLength = 24 }
        }

        @(Get-SafeScanTargets).Count | Should -Be 0
        $targets = @(Get-SafeScanTargets -AllowPublicProfile)
        $targets.Count | Should -Be 1
        $targets[0].profile | Should -Be 'Public'
        $targets[0].hostCount | Should -Be 254
    }
}

Describe '安全な既定動作の回帰防止' {
    It '引数なしのランナーは Basic モードで外部通信停止を診断へ渡す' {
        $source = Get-Content (Join-Path $scriptsDir 'Run-NetworkMapper.ps1') -Raw -Encoding UTF8
        $source | Should -Match "DefaultParameterSetName\s*=\s*'Basic'"
        $source | Should -Match 'NoExternalServices\s*=\s*\[bool\]\(-not \$allowExternal\)'
        $source | Should -Not -Match '\$wantSpeed\s*=\s*-not \$NoSpeedTest'
    }

    It '速度測定は HTTPS の Cloudflare だけを使い約200MBを既定上限にする' {
        $source = Get-Content (Join-Path $scriptsDir 'Test-NetworkHealth.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\[int\]\$SpeedTestMaxMB\s*=\s*180'
        $source | Should -Match '\[int\]\$SpeedTestUploadMB\s*=\s*20'
        $source | Should -Match 'https://speed\.cloudflare\.com/__down'
        $source | Should -Match "SpeedUA\s*=\s*'NetworkTopologyMapper/1\.0'"
        $source | Should -Not -Match 'proof\.ovh\.net|thinkbroadband|http://[^''"\s]+'
    }

    It 'ランチャーはスクリプト群を再帰的にブロック解除しない' {
        $launchers = @('Start.ps1', 'Start.bat', 'Run.vbs') | ForEach-Object {
            Get-Content (Join-Path $repoRoot $_) -Raw -Encoding UTF8
        }
        ($launchers -join "`n") | Should -Not -Match 'Unblock-File'
    }

    It 'トップメニューはフル実行を主操作にして5項目へ絞る' {
        $startPath = Join-Path $repoRoot 'Start.ps1'
        $menu = Get-ScriptFunctionSource -Path $startPath -Name 'Show-Menu'
        ([regex]::Matches($menu, '\[(?:1|2|O|H|Q)\]')).Count | Should -Be 5
        $menu | Should -Match 'フル実行'
        $menu | Should -Match 'その他の機能'
        $menu | Should -Not -Match '\[(?:3|V|F|S|P|L)\]'
    }

    It 'フル実行は診断・速度・通信品質・LAN調査を指定しレポート自動表示を止めない' {
        $startPath = Join-Path $repoRoot 'Start.ps1'
        $launcher = Get-Content $startPath -Raw -Encoding UTF8
        $lanReport = Get-ScriptFunctionSource -Path $startPath -Name 'Invoke-LanReport'
        $runner = Get-Content (Join-Path $scriptsDir 'Run-NetworkMapper.ps1') -Raw -Encoding UTF8

        $launcher | Should -Match '(?s)''1''\s*\{\s*Invoke-LanReport\s+-LightMode\s+\$script:lightMode\s+-IncludeInternet\s*\}'
        $lanReport | Should -Match 'DetailedScan\s*=\s*\$true'
        $lanReport | Should -Match 'AllowPublicProfile\s*=\s*\$true'
        $lanReport | Should -Match 'ExternalChecks\s*=\s*\$true'
        $lanReport | Should -Match 'SpeedTest\s*=\s*\$true'
        $lanReport | Should -Match 'IncludeMonitor\s*=\s*\$true'
        $lanReport | Should -Match 'MonitorDuration\s*=\s*60'
        $lanReport | Should -Not -Match 'NoOpen'
        $runner | Should -Match '&\s*\$diagnoseScript\s+@diagArgs'
        [regex]::IsMatch($runner, 'if\s*\(\$IncludeMonitor\).*?&\s*\$monitorScript\s+@monitorArgs', [Text.RegularExpressions.RegexOptions]::Singleline) | Should -BeTrue
        $runner | Should -Match '&\s*\$collectScript\s+@collectArgs'
        $runner | Should -Match '&\s*\$identifyScript\s+@identifyArgs'
        $runner | Should -Match '&\s*\$internetScript\s+@internetArgs'
        $runner | Should -Match '&\s*\$diagramScript\s+@diagramArgs'
        [regex]::IsMatch($runner, 'if\s*\(-not\s+\$NoOpen\)\s*\{\s*try\s*\{\s*Start-Process\s+\$htmlPath', [Text.RegularExpressions.RegexOptions]::Singleline) | Should -BeTrue
    }

    It '統合レポートのモニタには品質グラフと下り・上り速度を表示する' {
        $report = Get-Content (Join-Path $scriptsDir 'New-NetworkDiagram.ps1') -Raw -Encoding UTF8

        $report | Should -Match '<h2>遅延・瞬断モニタ</h2>'
        $report | Should -Match '<h2>通信速度</h2>'
        $report | Should -Match "key\s*=\s*'downloadMbps'"
        $report | Should -Match "key\s*=\s*'uploadMbps'"
        $report | Should -Match '通信速度の実測値を表で見る'
        $report | Should -Match 'まだ測定値がありません。メニューの「フル実行」'
        $report | Should -Match 'aria-label=.*遅延・損失グラフ'
        $report | Should -Match 'id\s*=\s*''health'';\s*label\s*=\s*''診断'';\s*html\s*=\s*\$healthSection'
        $report | Should -Match 'id\s*=\s*''monitor'';\s*label\s*=\s*''モニタ'';\s*html\s*=\s*\(\$monitorSection\s*\+.*\$trendSection\)'
    }

    It '通知は文字列コードを生成せず固定ヘルパーへデータとして渡す' {
        $scriptSources = Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' | ForEach-Object {
            Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        }
        ($scriptSources -join "`n") | Should -Not -Match 'Invoke-Expression'

        $sender = Get-Content (Join-Path $scriptsDir 'Send-NetworkAlert.ps1') -Raw -Encoding UTF8
        $helper = Get-Content (Join-Path $scriptsDir 'Show-NetworkToast.ps1') -Raw -Encoding UTF8
        $sender | Should -Match "'-TitleBase64'.*ConvertTo-Base64Text"
        $sender | Should -Not -Match 'WriteAllText|ntm-toast-'
        $helper | Should -Match "CreateElement\('toast'\)"
        $helper | Should -Match 'InnerText\s*=\s*\$value'
    }
}

Describe '公開用レポートの仮名化' {
    BeforeEach {
        Reset-PublicRedactionState
    }

    It 'IP・IPv6・MAC を同じ仮名へ決定論的に置き換える' {
        Protect-PublicText '192.168.1.20 / 192.168.1.20' | Should -Be '198.18.0.1 / 198.18.0.1'
        Protect-PublicText 'fe80::1234' | Should -Be '2001:db8::1'
        Protect-PublicText 'AA-BB-CC-DD-EE-FF / aa:bb:cc:dd:ee:ff' | Should -Be '02-00-00-00-00-01 / 02-00-00-00-00-01'
    }

    It '識別情報と利用アプリ一覧を公開用オブジェクトから除く' {
        $source = [PSCustomObject]@{
            metadata = [PSCustomObject]@{ hostname = 'PRIVATE-PC'; username = 'alice'; domain = 'HOME'; os = 'Windows' }
            wifi = [PSCustomObject]@{ ssid = 'SecretHome'; bssid = 'AA-BB-CC-DD-EE-FF' }
            adapters = @([PSCustomObject]@{
                name = 'My LAN'; description = 'Custom Adapter'; macAddress = 'AA-BB-CC-DD-EE-FF'
                ipv4Addresses = @([PSCustomObject]@{ address = '192.168.1.20'; prefixLength = 24 })
            })
            neighbors = @([PSCustomObject]@{ ipAddress = '192.168.1.1'; macAddress = '11-22-33-44-55-66' })
            hostnames = [PSCustomObject]@{ '192.168.1.1' = 'private-router.local' }
            deviceFingerprints = [PSCustomObject]@{
                '192.168.1.1' = [PSCustomObject]@{ friendlyName = 'Family Router'; serialNumber = 'SERIAL-SECRET' }
            }
            activeConnections = @([PSCustomObject]@{ processName = 'private-app'; remoteAddress = '203.0.113.9' })
            bandwidth = [PSCustomObject]@{ processes = @([PSCustomObject]@{ name = 'private-app' }) }
        }

        Initialize-PublicRedaction -Data $source
        $public = ConvertTo-PublicSafeObject -Value $source
        $json = $public | ConvertTo-Json -Depth 10

        foreach ($secret in @('PRIVATE-PC','alice','SecretHome','AA-BB-CC-DD-EE-FF','192.168.1.20',
                              '192.168.1.1','private-router.local','Family Router','SERIAL-SECRET','private-app')) {
            $json | Should -Not -Match ([regex]::Escape($secret))
        }
        @($public.activeConnections).Count | Should -Be 0
        @($public.bandwidth.processes).Count | Should -Be 0
        $public.deviceFingerprints.'198.18.0.2'.serialNumber | Should -Be '非公開'
    }
}

Describe 'AI修正依頼プロンプト' {
    It '複数問題を1本にまとめ、実測値と測定条件を含める' {
        $health = [PSCustomObject]@{
            summary = [PSCustomObject]@{
                overallStatus = 'warn'; total = 12; pass = 9; fail = 1; warn = 2; skip = 0
                likelyCauses = @(
                    [PSCustomObject]@{ severity = 'high'; area = '回線'; reason = '損失あり'; evidence = 'loss=7.5%'; action = '配線を確認' },
                    [PSCustomObject]@{ severity = 'medium'; area = '速度'; reason = 'リンク比が低い'; evidence = 'down=420.5 Mbps; link=1000 Mbps'; action = '再測定' }
                )
            }
            results = @(
                [PSCustomObject]@{
                    status = 'warn'; layer = '実測'; step = '実効スループット'; detail = '速度低下'
                    evidence = '4本並列'; hints = @('別時間帯で比較')
                    metrics = [PSCustomObject]@{ downloadMbps = 420.5; uploadMbps = 95.2; linkMbps = 1000; connections = 4 }
                },
                [PSCustomObject]@{ status = 'pass'; layer = 'L2'; step = 'NIC'; detail = '正常'; evidence = ''; hints = @(); metrics = $null }
            )
        }
        $monitor = [PSCustomObject]@{
            durationSec = 60; intervalMs = 1000
            targets = @([PSCustomObject]@{
                label = 'GW'; verdict = 'bad'; totalSamples = 60; lossCount = 6; lossPct = 10
                minMs = 1; medianMs = 2; avgMs = 8.4; maxMs = 120; jitterMs = 31.2
                spikeThreshold = 52; spikeCount = 3; outageCount = 2
            })
        }

        $r = New-AiRepairPrompt -Health $health -Monitor $monitor -GeneratedAt '2026-08-19 22:00:00'
        $r.hasIssues | Should -BeTrue
        $r.issueCount | Should -Be 3
        $r.text | Should -Match 'すべて、1つの連続した作業'
        $r.text | Should -Match 'loss=7\.5%'
        $r.text | Should -Match 'downloadMbps=420\.5; uploadMbps=95\.2; linkMbps=1000; connections=4'
        $r.text | Should -Match 'loss=6件 \(10%\).*max=120ms.*jitter=31\.2ms'
        $r.text | Should -Match 'duration=60秒; interval=1000ms'
    }

    It '正常だけなら修正対象なしとする' {
        $health = [PSCustomObject]@{
            summary = [PSCustomObject]@{
                overallStatus = 'pass'; total = 1; pass = 1; fail = 0; warn = 0; skip = 0
                likelyCauses = @([PSCustomObject]@{ area = '再現なし'; reason = '異常なし' })
            }
            results = @([PSCustomObject]@{ status = 'pass'; step = 'NIC' })
        }
        $r = New-AiRepairPrompt -Health $health
        $r.hasIssues | Should -BeFalse
        $r.issueCount | Should -Be 0
    }

    It '公開用診断から作った依頼文へ元の識別情報を戻さない' {
        Reset-PublicRedactionState
        $source = [PSCustomObject]@{ metadata = [PSCustomObject]@{ hostname = 'PRIVATE-PC'; username = 'alice' } }
        Initialize-PublicRedaction -Data $source
        $health = [PSCustomObject]@{
            summary = [PSCustomObject]@{
                overallStatus = 'warn'; total = 1; pass = 0; fail = 0; warn = 1; skip = 0
                likelyCauses = @([PSCustomObject]@{ severity = 'medium'; area = 'LAN'; reason = 'PRIVATE-PC が遅い'; evidence = '192.168.1.20 = 85 ms'; action = '確認' })
            }
            results = @([PSCustomObject]@{ status = 'warn'; layer = 'L3'; step = '遅延'; detail = 'PRIVATE-PC'; evidence = '192.168.1.20'; hints = @(); metrics = [PSCustomObject]@{ avgMs = 85 } })
        }
        $publicHealth = ConvertTo-PublicSafeObject -Value $health
        $prompt = (New-AiRepairPrompt -Health $publicHealth -PublicMode).text
        $prompt | Should -Not -Match 'PRIVATE-PC|192\.168\.1\.20'
        $prompt | Should -Match 'このPC|198\.18\.0\.1|avgMs=85'
    }

    It 'HTMLに専用タブ、TXT名、ワンクリックコピー処理がある' {
        $source = Get-Content (Join-Path $scriptsDir 'New-NetworkDiagram.ps1') -Raw -Encoding UTF8
        $source | Should -Match "label = 'AI修正依頼'"
        $source | Should -Match 'ai-repair-prompt-public\.txt'
        $source | Should -Match "getElementById\('copy-ai-prompt'\).*addEventListener\('click', copyAiPrompt\)"
    }
}

Describe 'ブロードキャスト/マルチキャストの除外' {
    It '端末でないエントリを弾く' {
        Test-SkipNeighbor -Ip '192.168.1.255'   -Mac 'FF-FF-FF-FF-FF-FF' | Should -BeTrue
        Test-SkipNeighbor -Ip '255.255.255.255' -Mac $null               | Should -BeTrue
        Test-SkipNeighbor -Ip '224.0.0.251'     -Mac '01-00-5E-00-00-FB' | Should -BeTrue
        Test-SkipNeighbor -Ip '239.255.255.250' -Mac $null               | Should -BeTrue
        Test-SkipNeighbor -Ip '192.168.1.10'    -Mac '33-33-00-00-00-01' | Should -BeTrue
        Test-SkipNeighbor -Ip ''                -Mac 'AA-BB-CC-DD-EE-FF' | Should -BeTrue
    }

    It '普通の端末は残す' {
        Test-SkipNeighbor -Ip '192.168.1.10' -Mac 'AA-BB-CC-DD-EE-FF' | Should -BeFalse
        Test-SkipNeighbor -Ip '10.0.0.2'     -Mac '02-00-00-00-00-02' | Should -BeFalse
    }
}

Describe '接続形態の線種' {
    It '帯域ごとに色が変わる' {
        (Get-LinkStyleSpec -Medium 'wired' -Band $null).label       | Should -Be '有線'
        (Get-LinkStyleSpec -Medium 'wifi'  -Band '6 GHz').label     | Should -Be 'Wi-Fi 6GHz'
        (Get-LinkStyleSpec -Medium 'wifi'  -Band '5 GHz').label     | Should -Be 'Wi-Fi 5GHz'
        (Get-LinkStyleSpec -Medium 'wifi'  -Band '2.4 GHz').label   | Should -Be 'Wi-Fi 2.4GHz'
        (Get-LinkStyleSpec -Medium 'wifi'  -Band '不明').label      | Should -Be 'Wi-Fi'
    }

    It '無線だけ破線になる' {
        (Get-LinkStyleSpec -Medium 'wired' -Band $null).dash    | Should -BeNullOrEmpty
        (Get-LinkStyleSpec -Medium 'wifi' -Band '5 GHz').dash   | Should -Match 'dasharray'
    }
}

Describe '電波強度の色分け' {
    It '<Pct>% は <Expected>' -ForEach @(
        @{ Pct = 100; Expected = '#009900' }
        @{ Pct = 50;  Expected = '#009900' }
        @{ Pct = 49;  Expected = '#E6A000' }
        @{ Pct = 25;  Expected = '#E6A000' }
        @{ Pct = 24;  Expected = '#CC0000' }
        @{ Pct = 0;   Expected = '#CC0000' }
    ) {
        Get-SignalColorFromPct -Pct $Pct | Should -Be $Expected
    }

    It '不明(null)は色を付けない' {
        Get-SignalColorFromPct -Pct $null | Should -BeNullOrEmpty
    }
}

Describe 'トレンド判定に使う中央値' {
    It '奇数個・偶数個のどちらでも正しい' {
        Get-Median -Values @(3, 1, 2)       | Should -Be 2
        Get-Median -Values @(4, 1, 3, 2)    | Should -Be 2.5
        Get-Median -Values @(7)             | Should -Be 7
    }

    It '空なら null' {
        Get-Median -Values @() | Should -BeNullOrEmpty
    }
}

Describe 'Mermaid ラベルのサニタイズ' {
    It 'HTML と Mermaid の引用符をエンティティ化し、アプリの改行だけを残す' {
        Format-MermaidLabel -Text 'PC "名前" [1]' | Should -Be 'PC &quot;名前&quot; [1]'
        Format-MermaidLabel -Text '<img src=x onerror=alert(1)><br/>次' |
            Should -Be '&lt;img src=x onerror=alert(1)&gt;<br/>次'
        Format-MermaidLabel -Text "前`n後" | Should -Be '前 後'
        Format-MermaidLabel -Text '' | Should -Be ''
    }

    It 'JavaScript 埋め込み値を JSON 化し script 終端を無害化する' {
        $original = '</script>${alert(1)}`'
        $encoded = ConvertTo-SafeJavaScriptJson -Value $original
        $encoded | Should -Not -Match '</script>'
        ($encoded | ConvertFrom-Json) | Should -Be $original
    }

    It 'Mermaid のスタイル値を許可リストに限定する' {
        Get-SafeHexColor -Value '#12aBcF' | Should -Be '#12aBcF'
        Get-SafeHexColor -Value "#fff;`nclick X" | Should -Be '#9ca3af'
        Get-SafeMermaidDash -Value ',stroke-dasharray:6 4' | Should -Be ',stroke-dasharray:6 4'
        Get-SafeMermaidDash -Value ',stroke:red' | Should -Be ''
        Get-SafeStrokeWidth -Value '2.5px' | Should -Be '2.5px'
        Get-SafeStrokeWidth -Value '2px,stroke:red' | Should -Be '2px'
    }

    It 'CSV の数式として解釈される値を文字列化する' {
        Protect-CsvCell -Value '=HYPERLINK("https://example.invalid")' | Should -Be '''=HYPERLINK("https://example.invalid")'
        Protect-CsvCell -Value '  +1+1' | Should -Be '''  +1+1'
        Protect-CsvCell -Value 'router-01' | Should -Be 'router-01'
    }

    It 'ノード ID は英数字と _ だけになる' {
        Get-NodeId -Prefix 'H' -Suffix '192.168.1.10' | Should -Be 'H_192_168_1_10'
        Get-NodeId -Prefix 'DNS' -Suffix 'fe80::1'    | Should -Be 'DNS_fe80__1'
    }
}

Describe 'Wi-Fi チャネルの推奨' {
    It '2.4GHz は 1/6/11 からしか勧めない' {
        $aps = @((New-Ap 1), (New-Ap 1), (New-Ap 1), (New-Ap 6))
        $r = Get-ChannelRecommendation -Entries $aps -CurrentChannel 1 -Is24 $true
        @(1, 6, 11) | Should -Contain $r.bestChannel
        @($r.candidates | ForEach-Object { $_.channel }) | Should -Be @(11, 6, 1)  # 空いている順
    }

    It '混んでいるチャネルから空いているチャネルへ誘導する' {
        # 現在 1ch に強い AP が 4 つ、11ch は無人
        $aps = @((New-Ap 1 90), (New-Ap 1 85), (New-Ap 1 80), (New-Ap 1 75))
        $r = Get-ChannelRecommendation -Entries $aps -CurrentChannel 1 -Is24 $true
        $r.shouldMove  | Should -BeTrue
        # 6 も 11 も 1ch から 5ch 以上離れており重ならない。どちらでも正解
        $r.bestChannel | Should -BeIn @(6, 11)
        $r.bestScore   | Should -Be 0
        $r.currentScore | Should -BeGreaterThan 0
    }

    It '差がわずかなら移動を勧めない' {
        # どのチャネルも似たような混み具合なら、変えても意味がない
        $aps = @((New-Ap 1 40), (New-Ap 6 40), (New-Ap 11 40))
        (Get-ChannelRecommendation -Entries $aps -CurrentChannel 1 -Is24 $true).shouldMove | Should -BeFalse
    }

    It '5GHz では DFS でないチャネルも併せて提示する' {
        # W52(36-48) が埋まっていて W56 が空いている状況
        $aps = @((New-Ap 36 90), (New-Ap 40 90), (New-Ap 44 90), (New-Ap 48 90))
        $r = Get-ChannelRecommendation -Entries $aps -CurrentChannel 36 -Is24 $false
        $r.shouldMove        | Should -BeTrue
        $r.bestIsDfs         | Should -BeTrue     # 空いているのは DFS 帯
        $r.bestNonDfsChannel | Should -BeIn @(36, 40, 44, 48)
    }

    It '弱い電波の AP は混雑として重く数えない' {
        $strong = Get-ChannelRecommendation -Entries @((New-Ap 1 90), (New-Ap 1 90)) -CurrentChannel 1 -Is24 $true
        $weak   = Get-ChannelRecommendation -Entries @((New-Ap 1 10), (New-Ap 1 10)) -CurrentChannel 1 -Is24 $true
        $weak.currentScore | Should -BeLessThan $strong.currentScore
    }

    It 'チャネル不明なら判定しない' {
        Get-ChannelRecommendation -Entries @((New-Ap 1)) -CurrentChannel $null -Is24 $true | Should -BeNullOrEmpty
    }
}

Describe 'インターネット側の情報' {
    BeforeAll {
        . ([scriptblock]::Create((Get-ScriptFunctionSource -Path (Join-Path $scriptsDir 'Get-InternetInfo.ps1') -Name @(
            'Test-PublicInternetAddress', 'ConvertTo-Ipv6Nibbles', 'Get-AccessMethod',
            'New-StunBindingRequest', 'Read-StunMappedAddress', 'Get-PortForwardingCapability'
        ))))
        $script:StunMagicCookie = [byte[]]@(0x21, 0x12, 0xA4, 0x42)

        function New-StunResponse {
            # XOR-MAPPED-ADDRESS を持つ Binding Success Response を組み立てる
            param([string]$Ip, [int]$Port)
            $cookie = [byte[]]@(0x21, 0x12, 0xA4, 0x42)
            $buf = New-Object System.Collections.Generic.List[byte]
            $buf.AddRange([byte[]]@(0x01, 0x01))          # Binding Success Response
            $buf.AddRange([byte[]]@(0x00, 0x0c))          # length = 12
            $buf.AddRange($cookie)
            $buf.AddRange((New-Object byte[] 12))         # transaction id
            $buf.AddRange([byte[]]@(0x00, 0x20))          # XOR-MAPPED-ADDRESS
            $buf.AddRange([byte[]]@(0x00, 0x08))          # length = 8
            $buf.Add(0x00)
            $buf.Add(0x01)                                # family = IPv4
            $xport = $Port -bxor 0x2112
            $buf.Add([byte](($xport -shr 8) -band 0xFF))
            $buf.Add([byte]($xport -band 0xFF))
            $ipb = ([System.Net.IPAddress]::Parse($Ip)).GetAddressBytes()
            for ($i = 0; $i -lt 4; $i++) { $buf.Add([byte]($ipb[$i] -bxor $cookie[$i])) }
            return $buf.ToArray()
        }
    }

    It 'IPv6 を逆順ニブルに変換する（origin6 照会用）' {
        # 2001:db8:: を完全展開すると 2001:0db8:0000:...:0000
        $n = ConvertTo-Ipv6Nibbles -Ip '2001:db8::1'
        $n | Should -Match '^1\.0\.0\.0\.'          # 末尾の 1 が先頭に来る
        $n | Should -Match '8\.b\.d\.0\.1\.0\.0\.2$'  # 先頭 2001:0db8 が末尾に来る
        ($n -split '\.').Count | Should -Be 32
    }

    It 'IPv4 を渡しても壊れない' {
        ConvertTo-Ipv6Nibbles -Ip '192.168.1.1' | Should -BeNullOrEmpty
    }

    It '外部サービスの戻り値は公開IPだけを受け入れる' {
        Test-PublicInternetAddress ([Net.IPAddress]::Parse('1.1.1.1')) | Should -BeTrue
        Test-PublicInternetAddress ([Net.IPAddress]::Parse('2606:4700:4700::1111')) | Should -BeTrue
        foreach ($address in @('192.168.1.1', '100.64.0.1', '198.18.0.1', '203.0.113.9', '::', 'fe80::1', 'fd00::1', '2001:db8::1')) {
            Test-PublicInternetAddress ([Net.IPAddress]::Parse($address)) | Should -BeFalse
        }
    }

    It '逆引き名から国内の接続方式を判定する' {
        (Get-AccessMethod -Ptr 'ai112247.d.east.v6connect.net').service | Should -Be 'v6コネクト'
        (Get-AccessMethod -Ptr 'x.xpass.jp').service                    | Should -Be 'クロスパス'
        (Get-AccessMethod -Ptr 'x.enabler.ne.jp').service               | Should -Be 'v6プラス (JPNE)'
        (Get-AccessMethod -Ptr 'x.vc.ocn.ne.jp').service                | Should -Be 'OCNバーチャルコネクト'
        (Get-AccessMethod -Ptr 'x.transix.jp').method                   | Should -Match 'DS-Lite'
        (Get-AccessMethod -Ptr 'ppp1234.tokyo.example.ne.jp').method    | Should -Be 'PPPoE'
    }

    It 'ルータの WAN 側 IP と外から見える IP が違えば共有IPと判定する' {
        $r = Get-AccessMethod -Ptr $null -GlobalV4 '203.0.113.9' `
             -WanInfo ([PSCustomObject]@{ externalIp = '100.64.0.5'; connectionStatus = 'Connected' })
        $r.method   | Should -Match 'CGN|共有'
        ($r.evidence -join ' ') | Should -Match '100\.64\.0\.5'
    }

    It 'STUN 要求は 20 バイトでマジッククッキーを含む' {
        $tid = New-Object byte[] 12
        $req = New-StunBindingRequest -TransactionId $tid
        $req.Length | Should -Be 20
        $req[0] | Should -Be 0x00
        $req[1] | Should -Be 0x01      # Binding Request
        @($req[4..7]) | Should -Be @(0x21, 0x12, 0xA4, 0x42)
    }

    It 'STUN 応答から外側アドレスを復元する（XOR 解除）' {
        $m = Read-StunMappedAddress -Data (New-StunResponse -Ip '203.0.113.45' -Port 51234)
        $m.ip   | Should -Be '203.0.113.45'
        $m.port | Should -Be 51234
    }

    It 'ポート番号が 256 以上でも壊れない' {
        # -shl のバイト幅マスクを踏むと上位バイトが落ちる
        foreach ($p in @(80, 255, 256, 4096, 32137, 65000)) {
            (Read-StunMappedAddress -Data (New-StunResponse -Ip '198.51.100.7' -Port $p)).port | Should -Be $p
        }
    }

    It 'STUN 応答でないものは無視する' {
        Read-StunMappedAddress -Data ([byte[]]@(0, 1, 0, 0)) | Should -BeNullOrEmpty
        Read-StunMappedAddress -Data @() | Should -BeNullOrEmpty
    }

    It '共有IP環境ではポート開放不可と判定する' {
        $r = Get-PortForwardingCapability -AccessMethod ([PSCustomObject]@{ method = 'IPv4 over IPv6 (MAP-E)' }) `
             -NatInfo ([PSCustomObject]@{ natType = 'Cone NAT'; mappedPorts = @(32137); localPort = 59927 }) `
             -GlobalV4 '203.0.113.9'
        $r.canForwardArbitraryPorts | Should -BeFalse
        ($r.reasons -join ' ') | Should -Match '59927'   # 書き換えを根拠として示す
    }

    It '共有IPでなくても着信テストなしにポート開放可能と断定しない' {
        $r = Get-PortForwardingCapability -AccessMethod ([PSCustomObject]@{ method = 'PPPoE' }) `
             -NatInfo ([PSCustomObject]@{ natType = 'Cone NAT'; mappedPorts = @(51234); localPort = 51234 }) `
             -WanInfo ([PSCustomObject]@{ externalIp = '203.0.113.9'; connectionStatus = 'Connected' }) `
             -GlobalV4 '203.0.113.9'
        $r.canForwardArbitraryPorts | Should -BeNullOrEmpty
        $r.summary | Should -Match '未確認'
    }

    It '外部情報取得は用途が公開されたサービスだけに限定する' {
        $source = Get-Content (Join-Path $scriptsDir 'Get-InternetInfo.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'https://api\.ipify\.org'
        $source | Should -Match 'https://api6\.ipify\.org'
        $source | Should -Match 'https://rdap\.org/ip/'
        $source | Should -Match "stun\.cloudflare\.com'.*3478"
        $source | Should -Not -Match 'icanhazip|checkip\.amazonaws|rdap\.apnic|stun\.l\.google|stun\.nextcloud|whoami\.ds\.akahelp|o-o\.myaddr'
    }

    It '手掛かりが無ければ不明、IPv6 があれば IPoE 扱い' {
        (Get-AccessMethod -Ptr $null).method                        | Should -Be '不明'
        (Get-AccessMethod -Ptr $null -HasGlobalV6 $true).method      | Should -Match 'IPoE'
    }
}

Describe '接続先ネットワークの識別' {
    # 出先と自宅では見える端末がまるごと入れ替わる。混ぜて比較しないための識別子。
    BeforeAll { $noOut = Join-Path $TestDrive 'nohealth' }

    It 'ルータの MAC で識別する' {
        $r = Get-NetworkIdentity -Data (New-NetData -GwMac 'AA-BB-CC-DD-EE-FF' -Ssid 'MyHome') -OutputDir $noOut
        $r.id | Should -Be 'gwAABBCCDDEEFF'
    }

    It 'サブネットが同じでもルータが違えば別ネットワークになる' {
        # 自宅も出先も 192.168.1.0/24 ということは珍しくない
        $homeNet = Get-NetworkIdentity -Data (New-NetData -GwIp '192.168.1.1' -GwMac 'AA-AA-AA-11-11-11' -Ssid 'MyHome') -OutputDir $noOut
        $cafeNet = Get-NetworkIdentity -Data (New-NetData -GwIp '192.168.1.1' -GwMac 'BB-BB-BB-22-22-22' -Ssid 'Cafe') -OutputDir $noOut
        $homeNet.id | Should -Not -Be $cafeNet.id
    }

    It '同じルータなら SSID 表記ゆれがあっても同一と判定する' {
        $a = Get-NetworkIdentity -Data (New-NetData -GwMac 'aa:bb:cc:dd:ee:ff' -Ssid 'MyHome') -OutputDir $noOut
        $b = Get-NetworkIdentity -Data (New-NetData -GwMac 'AA-BB-CC-DD-EE-FF' -Ssid 'MyHome-5G') -OutputDir $noOut
        $a.id | Should -Be $b.id
    }

    It '無線経路なら SSID を名前にする' {
        (Get-NetworkIdentity -Data (New-NetData -Ssid 'MyHome') -OutputDir $noOut).label | Should -Be 'MyHome'
    }

    It '有線経路なら Wi-Fi に繋がっていても SSID を名前にしない' {
        # 有線と Wi-Fi の同時接続時に、有線ネットワークへ SSID の名前を付けないこと
        $r = Get-NetworkIdentity -Data (New-NetData -WiredPath -Ssid 'MyHome') -OutputDir $noOut
        $r.label | Should -Not -Be 'MyHome'
        $r.label | Should -Match '192\.168\.1\.1'
    }

    It 'MAC が取れなければ SSID、それも無ければ IP で識別する' {
        $bySsid = Get-NetworkIdentity -Data (New-NetData -GwMac $null -Ssid 'MyHome') -OutputDir $noOut
        $bySsid.id | Should -Be 'ssidMyHome6'
        $byIp = Get-NetworkIdentity -Data (New-NetData -GwMac $null) -OutputDir $noOut
        $byIp.id | Should -Match '^ip'
    }
}

Describe '並列ワーカーの実行（速度測定の土台）' {
    It '指定した本数がすべて走り、結果が揃う' {
        $worker = { param([int]$N) [PSCustomObject]@{ value = $N * 2 } }
        $res = Invoke-ParallelWorkers -Worker $worker -ArgumentSets @(@(1), @(2), @(3))
        @($res).Count | Should -Be 3
        (@($res | ForEach-Object { $_.value }) | Sort-Object) | Should -Be @(2, 4, 6)
    }

    It '実際に同時実行される（直列なら合計時間になるところが短くなる）' {
        $worker = { param([int]$Ms) Start-Sleep -Milliseconds $Ms; [PSCustomObject]@{ ok = $true } }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $res = Invoke-ParallelWorkers -Worker $worker -ArgumentSets @(@(700), @(700), @(700), @(700))
        $sw.Stop()
        @($res).Count | Should -Be 4
        # 直列なら 2.8 秒。並列なら 0.7 秒 + 起動オーバーヘッド
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 2.5
    }

    It '失敗したワーカーがあっても他の結果は返る' {
        $worker = { param([int]$N) if ($N -eq 2) { throw '失敗' }; [PSCustomObject]@{ value = $N } }
        $res = Invoke-ParallelWorkers -Worker $worker -ArgumentSets @(@(1), @(2), @(3))
        @($res).Count | Should -Be 2
    }

    It '空の指定では何も走らない' {
        @(Invoke-ParallelWorkers -Worker { 1 } -ArgumentSets @()).Count | Should -Be 0
    }
}

Describe 'MAC の正規化' {
    It '区切り文字と大小文字を揃える' {
        Get-NormMac2 'aa:bb:cc:dd:ee:ff' | Should -Be 'AABBCCDDEEFF'
        Get-NormMac2 'AA-BB-CC-DD-EE-FF' | Should -Be 'AABBCCDDEEFF'
        Get-NormMac2 $null               | Should -BeNullOrEmpty
    }
}
