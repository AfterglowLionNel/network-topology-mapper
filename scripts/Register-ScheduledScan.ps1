<#
.SYNOPSIS
    定期実行をタスクスケジューラに登録・解除する。

.DESCRIPTION
    「たまに遅い」「夜だけ切れる」といった症状は、症状が出ている最中に測らないと
    捕まえられない。定期実行しておけば、あとから履歴トレンド（診断値の推移）と
    モニタ結果を見て、いつ・どこが悪かったのかを追える。

    登録されるタスクは以下の 2 種類:
      Diagnose … 診断のみ（約10秒、通信量ほぼゼロ）。既定は1日1回
      Monitor  … 連続ping監視（既定60秒）。既定は1日1回

    どちらも「ログオン中のユーザーとして」「最高権限なし」で動くため、
    管理者権限は不要（自分のタスクを自分で登録するだけ）。

.PARAMETER Mode
    Diagnose / Monitor / Both（既定 Both）

.PARAMETER Time
    実行時刻（HH:mm、既定 21:00）

.PARAMETER IntervalHours
    指定すると、その時間ごとに繰り返す（例: 6 なら6時間おき）

.PARAMETER MonitorDuration
    Monitor タスクの監視秒数（既定 60）

.PARAMETER Unregister
    登録済みタスクを削除する

.PARAMETER List
    登録状況を表示する

.EXAMPLE
    .\Register-ScheduledScan.ps1 -Mode Diagnose -Time 21:00

.EXAMPLE
    .\Register-ScheduledScan.ps1 -Mode Both -IntervalHours 6

.EXAMPLE
    .\Register-ScheduledScan.ps1 -Unregister
#>

[CmdletBinding()]
param(
    [ValidateSet('Diagnose', 'Monitor', 'Both')]
    [string]$Mode = 'Both',
    [string]$Time = '21:00',
    [int]$IntervalHours = 0,
    [int]$MonitorDuration = 60,
    # 既定では、問題を検出したときだけトースト通知を出す
    [switch]$NoNotify,
    [switch]$Unregister,
    [switch]$List
)

$ErrorActionPreference = "Stop"

$taskFolder = "\NetworkTopologyMapper"
$taskNames  = @{
    Diagnose = "NetworkTopologyMapper-Diagnose"
    Monitor  = "NetworkTopologyMapper-Monitor"
}

function Write-Step  { param([string]$M) Write-Host "[*] $M" -ForegroundColor Cyan }
function Write-Ok    { param([string]$M) Write-Host "[+] $M" -ForegroundColor Green }
function Write-Warn2 { param([string]$M) Write-Host "[!] $M" -ForegroundColor Yellow }

# ScheduledTasks モジュールが無い環境（一部の Windows Server Core 等）では動かせない
if (-not (Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)) {
    throw "この環境では ScheduledTasks モジュールが使えないため、定期実行を登録できません。"
}

function Get-RegisteredTasks {
    $found = @()
    foreach ($n in $taskNames.Values) {
        $t = Get-ScheduledTask -TaskName $n -TaskPath "$taskFolder\" -ErrorAction SilentlyContinue
        if ($t) { $found += $t }
    }
    return $found
}

if ($List) {
    $tasks = Get-RegisteredTasks
    if ($tasks.Count -eq 0) {
        Write-Host "定期実行は登録されていません。" -ForegroundColor Gray
    } else {
        foreach ($t in $tasks) {
            $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue
            $next = if ($info -and $info.NextRunTime) { $info.NextRunTime } else { "(未定)" }
            $last = if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 1999) { $info.LastRunTime } else { "(未実行)" }
            Write-Host ("{0}: 状態={1} / 次回={2} / 前回={3}" -f $t.TaskName, $t.State, $next, $last) -ForegroundColor White
        }
    }
    return
}

if ($Unregister) {
    $removed = 0
    foreach ($n in $taskNames.Values) {
        $t = Get-ScheduledTask -TaskName $n -TaskPath "$taskFolder\" -ErrorAction SilentlyContinue
        if ($t) {
            Unregister-ScheduledTask -TaskName $n -TaskPath "$taskFolder\" -Confirm:$false
            Write-Ok "削除: $n"
            $removed++
        }
    }
    if ($removed -eq 0) { Write-Warn2 "削除対象の登録済みタスクはありませんでした" }
    return
}

# 実行時刻の検証
$startAt = $null
try {
    $startAt = [datetime]::ParseExact($Time, 'HH:mm', $null)
} catch {
    throw "時刻は HH:mm 形式で指定してください（例: 21:00）。指定値: $Time"
}
# 今日のその時刻。過ぎていれば翌日から
$today = Get-Date
$startAt = Get-Date -Hour $startAt.Hour -Minute $startAt.Minute -Second 0
if ($startAt -lt $today) { $startAt = $startAt.AddDays(1) }

# PowerShell 7 があればそちらを使う（並列処理が効く）
$pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue)
$exe  = if ($pwsh) { $pwsh.Source } else { Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe" }
$runner = Join-Path $PSScriptRoot "Run-NetworkMapper.ps1"
if (-not (Test-Path $runner)) { throw "Run-NetworkMapper.ps1 が見つかりません: $runner" }

function New-MapperTask {
    param([string]$Name, [string]$Arguments, [string]$Description)

    $action = New-ScheduledTaskAction -Execute $exe `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$runner"" $Arguments" `
        -WorkingDirectory $PSScriptRoot

    if ($IntervalHours -gt 0) {
        # 「指定間隔で繰り返す」: 初回を $startAt にして、以後 N 時間ごと（1日分の繰り返しを毎日更新）
        $trigger = New-ScheduledTaskTrigger -Once -At $startAt `
            -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) `
            -RepetitionDuration ([TimeSpan]::FromDays(3650))
    } else {
        $trigger = New-ScheduledTaskTrigger -Daily -At $startAt
    }

    # ノートPCでバッテリー駆動でも動かす（電源条件で黙って実行されないのを防ぐ）
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew

    # ログオン中のユーザーとして実行（管理者権限不要・パスワード保存なし）
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask -TaskName $Name -TaskPath "$taskFolder\" `
        -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
        -Description $Description -Force | Out-Null

    Write-Ok "登録: $Name"
}

Write-Step "定期実行を登録中（実行ファイル: $(Split-Path -Leaf $exe)）..."

# 定期実行は画面を見ていないので、通知を付けないと変化に気づけない
$notifyArg = if ($NoNotify) { "" } else { " -Notify" }

if ($Mode -eq 'Diagnose' -or $Mode -eq 'Both') {
    New-MapperTask -Name $taskNames.Diagnose `
        -Arguments "-DiagnoseOnly$notifyArg" `
        -Description "ネットワーク診断を定期実行し、診断値の推移を output\history に蓄積します。問題を検出したときだけ通知します。"
}

if ($Mode -eq 'Monitor' -or $Mode -eq 'Both') {
    New-MapperTask -Name $taskNames.Monitor `
        -Arguments "-Monitor -MonitorDuration $MonitorDuration" `
        -Description "連続 ping で遅延スパイク/瞬断を定期監視します。"
}

Write-Host ""
$scheduleText = if ($IntervalHours -gt 0) { "$IntervalHours 時間ごと（初回 $($startAt.ToString('yyyy-MM-dd HH:mm'))）" } else { "毎日 $($startAt.ToString('HH:mm'))" }
Write-Host "スケジュール: $scheduleText" -ForegroundColor White
Write-Host "結果は output\history に溜まり、次回レポート生成時に「診断値の推移」タブへ反映されます。" -ForegroundColor Gray
Write-Host "解除する場合: .\Register-ScheduledScan.ps1 -Unregister" -ForegroundColor Gray
