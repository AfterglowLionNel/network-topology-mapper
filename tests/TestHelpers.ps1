<#
.SYNOPSIS
    テスト用ヘルパー: スクリプト本体を実行せずに、関数定義だけを取り出す。

.DESCRIPTION
    このプロジェクトのスクリプトは読み込むと即座に処理を始める（引数の検証、
    ファイル読み込み、実際のネットワークアクセス）ため、ドットソースでは
    ユニットテストできない。ここでは AST から関数定義のソースだけを取り出して返す。

    呼び出し側で次のように読み込む:
        . ([scriptblock]::Create((Get-ScriptFunctionSource -Path $p -Name 'Foo','Bar')))
#>

function Get-ScriptFunctionSource {
    param(
        [Parameter(Mandatory)][string]$Path,
        # 取り出す関数名。省略時はすべての関数
        [string[]]$Name
    )
    if (-not (Test-Path $Path)) { throw "スクリプトが見つかりません: $Path" }

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        throw "構文エラーのため読み込めません ($Path): $($errors[0].Message)"
    }

    $defs = $ast.FindAll({
        param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
    }, $true)

    $parts = @()
    foreach ($d in $defs) {
        if ($Name -and $d.Name -notin $Name) { continue }
        $parts += $d.Extent.Text
    }
    if ($Name) {
        $missing = @($Name | Where-Object { $_ -notin @($defs.Name) })
        if ($missing.Count -gt 0) {
            throw "指定した関数が見つかりません ($Path): $($missing -join ', ')"
        }
    }
    return ($parts -join "`n`n")
}

function New-DnsTestPacket {
    <#
        mDNS 応答パケットを組み立てる（パーサのテスト用）。
        $Records は @{ type; name; value } の配列:
          type 1  = A    (value: "192.168.1.50")
          type 12 = PTR  (value: インスタンス名)
          type 16 = TXT  (value: "key=val" の配列)
        $CompressLastName を指定すると、最後のレコードの名前を
        最初のレコードへの圧縮ポインタで表現する（0xC0 の経路を通す）。
    #>
    param(
        [array]$Records,
        [switch]$CompressLastName
    )
    $buf = New-Object System.Collections.Generic.List[byte]
    $addU16 = {
        param($list, [int]$v)
        $list.Add([byte](($v -shr 8) -band 0xFF))
        $list.Add([byte]($v -band 0xFF))
    }
    $addName = {
        param($list, [string]$n)
        foreach ($label in $n.Split('.')) {
            if (-not $label) { continue }
            $b = [System.Text.Encoding]::UTF8.GetBytes($label)
            $list.Add([byte]$b.Length)
            $list.AddRange($b)
        }
        $list.Add(0)
    }

    & $addU16 $buf 0        # ID
    & $addU16 $buf 0x8400   # Flags: 応答
    & $addU16 $buf 0        # QDCOUNT
    & $addU16 $buf $Records.Count
    & $addU16 $buf 0        # NSCOUNT
    & $addU16 $buf 0        # ARCOUNT

    $firstNameOffset = $null
    for ($i = 0; $i -lt $Records.Count; $i++) {
        $r = $Records[$i]
        $isLast = ($i -eq $Records.Count - 1)
        if ($CompressLastName -and $isLast -and $null -ne $firstNameOffset) {
            $buf.Add([byte](0xC0 -bor (($firstNameOffset -shr 8) -band 0x3F)))
            $buf.Add([byte]($firstNameOffset -band 0xFF))
        } else {
            if ($null -eq $firstNameOffset) { $firstNameOffset = $buf.Count }
            & $addName $buf $r.name
        }
        & $addU16 $buf ([int]$r.type)
        & $addU16 $buf 1        # CLASS=IN
        & $addU16 $buf 0        # TTL 上位
        & $addU16 $buf 120      # TTL 下位

        $rd = New-Object System.Collections.Generic.List[byte]
        switch ([int]$r.type) {
            1  { foreach ($o in ([string]$r.value).Split('.')) { $rd.Add([byte][int]$o) } }
            12 { & $addName $rd ([string]$r.value) }
            16 {
                foreach ($s in @($r.value)) {
                    $b = [System.Text.Encoding]::UTF8.GetBytes([string]$s)
                    $rd.Add([byte]$b.Length)
                    $rd.AddRange($b)
                }
            }
        }
        & $addU16 $buf $rd.Count
        $buf.AddRange($rd)
    }
    return $buf.ToArray()
}
