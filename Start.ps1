<#
.SYNOPSIS
    Network Topology Mapper - メニュー式ランチャー

.DESCRIPTION
    Start.bat からダブルクリックで起動される、対話メニュー付きのランチャー。
    IT 知識がない利用者でもメニューから番号を選ぶだけで実行できる。
#>

try {
    $Host.UI.RawUI.WindowTitle = "Network Topology Mapper"
} catch { }

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$mainScript = Join-Path $scriptDir "scripts\Run-NetworkMapper.ps1"

function Write-Header {
    Write-Host ""
    Write-Host "  +================================================+" -ForegroundColor Cyan
    Write-Host "  |    Network Topology Mapper                     |" -ForegroundColor Cyan
    Write-Host "  |    ネットワーク構成図 + 診断ツール             |" -ForegroundColor Cyan
    Write-Host "  +================================================+" -ForegroundColor Cyan
    $psv = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    Write-Host "  PowerShell バージョン: $psv" -ForegroundColor DarkGray
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Host "  ※ PowerShell 7 が未導入です。[2] 詳細LAN調査では導入案内を表示します（無くても動作します）" -ForegroundColor DarkGray
    }
    Write-Host ""
}

function Show-Menu {
    param([bool]$LightMode)

    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  メニュー" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [1] " -NoNewline -ForegroundColor Cyan
    Write-Host "基本診断" -ForegroundColor Green -NoNewline
    Write-Host " (推奨)              約10秒  PC・NIC・ルーターまでを確認" -ForegroundColor DarkGray
    Write-Host "                                  (LAN全探索・外部サービス通信なし)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [2] " -NoNewline -ForegroundColor Cyan
    Write-Host "詳細LAN調査" -ForegroundColor White -NoNewline
    Write-Host "                 約1-5分  構成図と機器情報を作る" -ForegroundColor DarkGray
    Write-Host "                                  (対象範囲を表示し、確認後に開始)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [V] " -NoNewline -ForegroundColor Cyan
    Write-Host "インターネット速度測定" -ForegroundColor White -NoNewline
    Write-Host "       Cloudflareへ最大 約200MB" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [3] " -NoNewline -ForegroundColor Cyan
    Write-Host "モニタモード" -ForegroundColor White -NoNewline
    Write-Host "               約60秒  ルーターへの遅延スパイク/瞬断を監視" -ForegroundColor DarkGray
    Write-Host "                                  (たまに遅い/切れる時に)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [F] " -NoNewline -ForegroundColor Cyan
    Write-Host "設定の不備を修正" -ForegroundColor White -NoNewline
    Write-Host "           診断で見つかったPC側の設定を直す" -ForegroundColor DarkGray
    Write-Host "                                  (内容を確認してから適用/元に戻せます)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [S] " -NoNewline -ForegroundColor Cyan
    Write-Host "定期実行の設定" -ForegroundColor White -NoNewline
    Write-Host "             毎日決まった時刻に診断/監視を自動実行" -ForegroundColor DarkGray
    Write-Host "                                  (推移グラフが溜まり比較できます)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [O] " -NoNewline -ForegroundColor Cyan
    Write-Host "前回の結果を開く" -ForegroundColor White -NoNewline
    Write-Host "           output\diagram.html を表示" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [P] " -NoNewline -ForegroundColor Cyan
    Write-Host "公開用レポートを作る" -ForegroundColor White -NoNewline
    Write-Host "         識別情報を仮名化して別ファイルへ保存" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [H] " -NoNewline -ForegroundColor Cyan
    Write-Host "ヘルプ" -ForegroundColor White -NoNewline
    Write-Host "                     使い方・結果の見方をブラウザで開く" -ForegroundColor DarkGray
    Write-Host ""
    $lightState = if ($LightMode) { "ON " } else { "OFF" }
    $lightColor = if ($LightMode) { "Green" } else { "DarkGray" }
    Write-Host "    [L] " -NoNewline -ForegroundColor Cyan
    Write-Host "軽量モード切替 [" -ForegroundColor White -NoNewline
    Write-Host $lightState -ForegroundColor $lightColor -NoNewline
    Write-Host "]" -ForegroundColor White -NoNewline
    Write-Host "    機器が多い環境で [2] を高速化" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [Q] " -NoNewline -ForegroundColor DarkGray
    Write-Host "終了" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    if ($LightMode) {
        Write-Host "  ※ 軽量モード ON: 重い機器特定(NetBIOS/HTTP)を省略し高速描画します" -ForegroundColor Green
        Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    }
}

function Invoke-MapperWithArgs {
    param([hashtable]$ScriptParameters)

    if (-not (Test-Path $mainScript)) {
        Write-Host ""
        Write-Host "  [ERROR] $mainScript が見つかりません" -ForegroundColor Red
        Write-Host "          Start.bat と同じフォルダに scripts\Run-NetworkMapper.ps1 が必要です" -ForegroundColor Yellow
        Read-Host "  Enter で戻る"
        return
    }

    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "  実行開始..." -ForegroundColor Cyan
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host ""

    try {
        & $mainScript @ScriptParameters
        Write-Host ""
        Write-Host "  [OK] 実行完了しました" -ForegroundColor Green
    } catch {
        Write-Host ""
        Write-Host "  [ERROR] 実行中にエラーが発生しました:" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "  対処方法:" -ForegroundColor Yellow
        Write-Host "    1. もう一度試してみる" -ForegroundColor White
        Write-Host "    2. PowerShell 7 をインストールして試す" -ForegroundColor White
        Write-Host "       (winget install --id Microsoft.PowerShell)" -ForegroundColor White
        Write-Host "    3. docs\README.md のトラブルシューティングを参照" -ForegroundColor White
    }

    Write-Host ""
    Read-Host "  Enter キーでメニューに戻る"
}

function Invoke-SettingRepair {
    $repairScript = Join-Path $scriptDir "scripts\Repair-NetworkSetting.ps1"
    $healthPath   = Join-Path $scriptDir "output\network-health.json"
    if (-not (Test-Path $repairScript)) {
        Write-Host ""
        Write-Host "  [ERROR] $repairScript が見つかりません" -ForegroundColor Red
        Read-Host "  Enter で戻る"
        return
    }
    if (-not (Test-Path $healthPath)) {
        Write-Host ""
        Write-Host "  先に [1] 基本診断 または [2] 詳細LAN調査を実行してください（診断結果をもとに修正内容を決めます）" -ForegroundColor Yellow
        Read-Host "  Enter で戻る"
        return
    }

    Write-Host ""
    Write-Host "  設定の不備を修正" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  直近の診断で見つかった、PC 側の設定の不備を直します。" -ForegroundColor Gray
    Write-Host "  ルーターの設定や機器交換など、判断が要るものは対象外です。" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    [1] 何が直せるか見るだけ（変更しない）" -ForegroundColor White
    Write-Host "    [2] 内容を確認して適用する" -ForegroundColor White
    Write-Host "    [3] 直前の変更を元に戻す" -ForegroundColor White
    Write-Host "    [B] 戻る" -ForegroundColor DarkGray
    Write-Host ""
    $sel = (Read-Host "  番号を入力してください").Trim().ToUpper()

    try {
        switch ($sel) {
            '1' { & $repairScript -WhatIfOnly }
            '2' { & $repairScript }
            '3' { & $repairScript -Rollback }
            'B' { return }
            default { Write-Host "  '$sel' は無効な選択です" -ForegroundColor Red }
        }
    } catch {
        Write-Host ""
        Write-Host "  [ERROR] 実行に失敗しました: $_" -ForegroundColor Red
    }

    Write-Host ""
    Read-Host "  Enter キーでメニューに戻る"
}

function Set-ScheduledScan {
    $schedScript = Join-Path $scriptDir "scripts\Register-ScheduledScan.ps1"
    if (-not (Test-Path $schedScript)) {
        Write-Host ""
        Write-Host "  [ERROR] $schedScript が見つかりません" -ForegroundColor Red
        Read-Host "  Enter で戻る"
        return
    }

    Write-Host ""
    Write-Host "  定期実行の設定" -ForegroundColor Yellow
    Write-Host "  ----------------------------------------" -ForegroundColor DarkGray
    Write-Host "  毎日決まった時刻に自動で診断/監視を行い、結果を蓄積します。" -ForegroundColor Gray
    Write-Host "  溜まった結果はレポートの「診断」タブに推移グラフとして表示され、" -ForegroundColor Gray
    Write-Host "  「先週より遅くなった」といった変化が分かるようになります。" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    [1] 診断のみを毎日実行      約10秒 / 通信量ほぼゼロ" -ForegroundColor White
    Write-Host "    [2] 診断 + 監視を毎日実行   約70秒" -ForegroundColor White
    Write-Host "    [3] 登録状況を確認" -ForegroundColor White
    Write-Host "    [4] 定期実行を解除" -ForegroundColor White
    Write-Host "    [B] 戻る" -ForegroundColor DarkGray
    Write-Host ""
    $sel = (Read-Host "  番号を入力してください").Trim().ToUpper()

    try {
        switch ($sel) {
            '1' {
                $tm = Read-Host "  実行時刻を入力 (HH:mm、空Enterで 21:00)"
                if (-not $tm) { $tm = '21:00' }
                & $schedScript -Mode Diagnose -Time $tm
            }
            '2' {
                $tm = Read-Host "  実行時刻を入力 (HH:mm、空Enterで 21:00)"
                if (-not $tm) { $tm = '21:00' }
                & $schedScript -Mode Both -Time $tm
            }
            '3' { & $schedScript -List }
            '4' { & $schedScript -Unregister }
            'B' { return }
            default { Write-Host "  '$sel' は無効な選択です" -ForegroundColor Red }
        }
    } catch {
        Write-Host ""
        Write-Host "  [ERROR] 設定に失敗しました: $_" -ForegroundColor Red
    }

    Write-Host ""
    Read-Host "  Enter キーでメニューに戻る"
}

function Open-Help {
    $helpPath = Join-Path $scriptDir "docs\help.html"
    if (Test-Path $helpPath) {
        try {
            Start-Process $helpPath
            Write-Host "  ヘルプをブラウザで開きました" -ForegroundColor Green
        } catch {
            Write-Host "  ブラウザを自動起動できませんでした: $helpPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ヘルプファイルが見つかりません: $helpPath" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 2
}

function Install-Pwsh7 {
    # PowerShell 7 を winget で導入し、成功したら新しい pwsh でこのメニューを開き直す。
    # 戻り値: $true = 再起動済み（呼び出し側はそのまま exit する）
    Write-Host ""
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        # winget が無い環境（古い Windows 10 等）は公式ページへ誘導する
        Write-Host "  この PC では自動インストールに必要な winget が見つかりません。" -ForegroundColor Yellow
        Write-Host "  ブラウザでダウンロードページを開きます。「PowerShell-7.x.x-win-x64.msi」を" -ForegroundColor White
        Write-Host "  ダウンロードして実行し、終わったらこのツールを起動し直してください。" -ForegroundColor White
        try { Start-Process 'https://aka.ms/PSWindows' } catch { }
        Read-Host "  Enter でメニューに戻る"
        return $false
    }

    Write-Host "  PowerShell 7 をインストールします（無料・数分。途中で Windows の許可画面が出ます）..." -ForegroundColor Cyan
    Write-Host ""
    try {
        & winget.exe install --id Microsoft.PowerShell --source winget --accept-package-agreements --accept-source-agreements
    } catch {
        Write-Host "  [ERROR] インストールの実行に失敗しました: $_" -ForegroundColor Red
    }

    # インストール先を確認（winget の exit code は環境差があるため、実体の有無で判定する）
    $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
    if (-not (Test-Path $pwshPath)) {
        $cmd = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if ($cmd) { $pwshPath = $cmd.Source }
    }
    if ($pwshPath -and (Test-Path $pwshPath)) {
        Write-Host ""
        Write-Host "  インストール完了。PowerShell 7 でメニューを開き直します..." -ForegroundColor Green
        Start-Sleep -Seconds 1
        try {
            Start-Process $pwshPath -ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
            return $true
        } catch {
            Write-Host "  開き直しに失敗しました。ツールをもう一度起動してください（自動で PowerShell 7 が使われます）" -ForegroundColor Yellow
            Read-Host "  Enter でメニューに戻る"
            return $false
        }
    }

    Write-Host ""
    Write-Host "  インストールを確認できませんでした。キャンセルした場合はそのままでも実行できます。" -ForegroundColor Yellow
    Read-Host "  Enter でメニューに戻る"
    return $false
}

function Open-LastResult {
    $htmlPath = Join-Path $scriptDir "output\diagram.html"
    if (Test-Path $htmlPath) {
        try {
            Start-Process $htmlPath
            Write-Host "  ブラウザで開きました" -ForegroundColor Green
        } catch {
            Write-Host "  ブラウザを自動起動できませんでした: $htmlPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  まだレポートが生成されていません。先にメニュー [2] を実行してください" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds 2
}

# ====================================================================
# メインループ
# ====================================================================
$lightMode = $false

while ($true) {
    if (-not [Console]::IsInputRedirected) {
        Clear-Host
    }
    Write-Header
    Show-Menu -LightMode $lightMode

    Write-Host ""
    $choice = Read-Host "  番号を入力してください"
    $choice = $choice.Trim().ToUpper()

    switch ($choice) {
        '1' {
            Invoke-MapperWithArgs -ScriptParameters @{}
        }
        '2' {
            if ($PSVersionTable.PSVersion.Major -lt 7) {
                Write-Host ""
                Write-Host "  PowerShell 7 が見つかりません。無くても動きますが、" -ForegroundColor Yellow
                Write-Host "  導入すると機器の調査が数倍速くなります（無料・数分）。" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "    [1] PowerShell 7 を今インストールする (推奨)" -ForegroundColor White
                Write-Host "    [2] このまま実行する（動作は同じ・時間がかかる）" -ForegroundColor White
                Write-Host "    [B] 戻る" -ForegroundColor DarkGray
                Write-Host ""
                $sel = (Read-Host "  番号を入力してください").Trim().ToUpper()
                if ($sel -eq '1') {
                    if (Install-Pwsh7) { exit 0 }   # 新しい pwsh でメニューが開き直されている
                    continue
                }
                if ($sel -ne '2') { continue }
            }
            $p = @{ DetailedScan = $true }
            if ($lightMode) { $p.Light = $true }
            Write-Host ""
            Write-Host "  公開IP・回線情報・メーカー情報も確認する場合は、外部サービスへ通信します。" -ForegroundColor Yellow
            Write-Host "  通信先と送信内容は docs\NETWORK_SERVICES.md で確認できます。速度測定は含みません。" -ForegroundColor DarkGray
            $external = (Read-Host "  外部情報も取得しますか？ [y/N]").Trim().ToUpper()
            if ($external -eq 'Y') { $p.ExternalChecks = $true }
            Invoke-MapperWithArgs -ScriptParameters $p
        }
        'V' {
            Write-Host ""
            Write-Host "  Cloudflare の測定先へデータを送受信します。" -ForegroundColor Yellow
            Write-Host "  通信量の上限: 下り 約180MB + 上り 約20MB（合計 約200MB）" -ForegroundColor Yellow
            $st = (Read-Host "  速度を測定しますか？ [y/N]").Trim().ToUpper()
            if ($st -eq 'Y') {
                Invoke-MapperWithArgs -ScriptParameters @{
                    DiagnoseOnly     = $true
                    SpeedTest        = $true
                    SpeedTestMaxMB   = 180
                    SpeedTestUploadMB = 20
                }
            }
        }
        '3' {
            Write-Host ""
            $durInput = Read-Host "  監視する秒数を入力 (空Enterで60秒)"
            $dur = 60
            if ($durInput -match '^\d+$') { $dur = [int]$durInput }
            $ext = (Read-Host "  インターネット側(8.8.8.8)も監視しますか？ [y/N]").Trim().ToUpper()
            $monitorParameters = @{ Monitor = $true; MonitorDuration = $dur }
            if ($ext -eq 'Y') { $monitorParameters.ExternalChecks = $true }
            Invoke-MapperWithArgs -ScriptParameters $monitorParameters
        }
        'L' {
            $lightMode = -not $lightMode
            $msg = if ($lightMode) { "軽量モードを ON にしました" } else { "軽量モードを OFF にしました" }
            Write-Host ""
            Write-Host "  $msg" -ForegroundColor Green
            Start-Sleep -Milliseconds 700
        }
        'F' { Invoke-SettingRepair }
        'S' { Set-ScheduledScan }
        'O' { Open-LastResult }
        'P' { Invoke-MapperWithArgs -ScriptParameters @{ PublicReport = $true } }
        'H' { Open-Help }
        'Q' {
            Write-Host ""
            Write-Host "  終了します" -ForegroundColor Cyan
            Start-Sleep -Milliseconds 500
            exit 0
        }
        '' {
            # Enter のみは無視
        }
        default {
            Write-Host ""
            Write-Host "  '$choice' は無効な選択です。1〜3, V, F, S, L, O, P, H, Q から選んでください" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
