<#
.SYNOPSIS
    Send-NetworkAlert.ps1 専用の Windows トースト表示ヘルパー。

.DESCRIPTION
    Windows PowerShell 5.1 の WinRT 型投影を使って通知を表示する。
    呼び出し元から受け取る値は UTF-8 Base64 として復号し、XML DOM の InnerText
    へ設定するため、通知文や機器名を PowerShell コードまたは XML として評価しない。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9+/]*={0,2}$')][string]$TitleBase64,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9+/]*={0,2}$')][string]$MessageBase64,
    [Parameter(Mandatory)][AllowEmptyString()][ValidatePattern('^[A-Za-z0-9+/]*={0,2}$')][string]$LaunchPathBase64
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-Base64Text {
    param([string]$Value, [int]$MaxCharacters)
    $text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
    if ($text.Length -gt $MaxCharacters) { throw "通知データが長すぎます（上限 $MaxCharacters 文字）" }
    return $text
}

try {
    $title = ConvertFrom-Base64Text -Value $TitleBase64 -MaxCharacters 128
    $message = ConvertFrom-Base64Text -Value $MessageBase64 -MaxCharacters 1024
    $launchPath = ConvertFrom-Base64Text -Value $LaunchPathBase64 -MaxCharacters 32767
    if ([string]::IsNullOrWhiteSpace($title)) { throw '通知タイトルが空です' }

    $launchUri = $null
    if (-not [string]::IsNullOrWhiteSpace($launchPath)) {
        $fullPath = [IO.Path]::GetFullPath($launchPath)
        if ([IO.Path]::GetExtension($fullPath) -ieq '.html' -and [IO.File]::Exists($fullPath)) {
            $launchUri = ([Uri]$fullPath).AbsoluteUri
        }
    }

    $xml = New-Object System.Xml.XmlDocument
    $toastElement = $xml.CreateElement('toast')
    if ($launchUri) {
        $toastElement.SetAttribute('activationType', 'protocol')
        $toastElement.SetAttribute('launch', $launchUri)
    }
    [void]$xml.AppendChild($toastElement)

    $visualElement = $xml.CreateElement('visual')
    [void]$toastElement.AppendChild($visualElement)
    $bindingElement = $xml.CreateElement('binding')
    $bindingElement.SetAttribute('template', 'ToastGeneric')
    [void]$visualElement.AppendChild($bindingElement)

    foreach ($value in @($title, $message)) {
        $textElement = $xml.CreateElement('text')
        $textElement.InnerText = $value
        [void]$bindingElement.AppendChild($textElement)
    }

    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime]
    $winDocument = New-Object Windows.Data.Xml.Dom.XmlDocument
    $winDocument.LoadXml($xml.OuterXml)
    $notification = New-Object Windows.UI.Notifications.ToastNotification($winDocument)
    $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($notification)
    exit 0
} catch {
    Write-Error $_
    exit 1
}
