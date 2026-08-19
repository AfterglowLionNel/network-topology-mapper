<#
.SYNOPSIS
    ユニットテストを実行する。

.DESCRIPTION
    Pester 6 が必要。Windows に同梱されている旧版では動かないため、
    見つからなければ %LOCALAPPDATA%\NetworkTopologyMapper\Modules に取得する
    （システムの Pester には触らないので管理者権限は不要）。

    テストはネットワークにアクセスせず、コマンド出力を模したテキストと
    組み立てたパケットだけを使うため、いつ実行しても結果が変わらない。

.EXAMPLE
    .\tests\Invoke-Tests.ps1

.EXAMPLE
    .\tests\Invoke-Tests.ps1 -Detailed
#>

[CmdletBinding()]
param(
    [switch]$Detailed
)

$ErrorActionPreference = 'Stop'

$localModules = Join-Path $env:LOCALAPPDATA 'NetworkTopologyMapper\Modules'
if (Test-Path $localModules) {
    if ($env:PSModulePath -notlike "*$localModules*") {
        $env:PSModulePath = "$localModules;$env:PSModulePath"
    }
}

$pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -eq 6 } |
          Sort-Object Version -Descending | Select-Object -First 1

if (-not $pester) {
    Write-Host "[*] Pester 6 が見つからないため、固定版 6.0.0 を取得します（$localModules）..." -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Path $localModules -Force | Out-Null
        Save-Module -Name Pester -RequiredVersion 6.0.0 -Path $localModules -Force -ErrorAction Stop
        if ($env:PSModulePath -notlike "*$localModules*") {
            $env:PSModulePath = "$localModules;$env:PSModulePath"
        }
        $pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -eq 6 } |
                  Sort-Object Version -Descending | Select-Object -First 1
    } catch {
        throw "Pester 6.0.0 を取得できませんでした。手動で導入してください: Save-Module Pester -RequiredVersion 6.0.0 -Path '$localModules'`n$_"
    }
}

Import-Module $pester.Path -Force
Write-Host "[+] Pester $($pester.Version) を使用" -ForegroundColor Green

$config = New-PesterConfiguration
$config.Run.Path = $PSScriptRoot
$config.Output.Verbosity = if ($Detailed) { 'Detailed' } else { 'Normal' }
$config.Run.Exit = $true

Invoke-Pester -Configuration $config
