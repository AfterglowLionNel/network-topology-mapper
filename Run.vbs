' Network Topology Mapper - VBScript Launcher
' Keep this file ASCII-only for maximum compatibility with wscript.exe.

Option Explicit

Dim shell, fso, scriptDir, startPs1, psExe, commandLine, exitCode

Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
startPs1 = fso.BuildPath(scriptDir, "Start.ps1")

If Not fso.FileExists(startPs1) Then
    MsgBox "Start.ps1 was not found." & vbCrLf & scriptDir, vbCritical, "Network Topology Mapper"
    WScript.Quit 1
End If

psExe = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"

If shell.Run("cmd.exe /c where pwsh.exe >nul 2>nul", 0, True) = 0 Then
    If shell.Run("pwsh.exe -NoLogo -NoProfile -Command ""exit 0""", 0, True) = 0 Then
        psExe = "pwsh.exe"
    End If
End If

commandLine = """" & psExe & """ -NoLogo -NoProfile -ExecutionPolicy Bypass -File """ & startPs1 & """"
exitCode = shell.Run(commandLine, 1, True)

If exitCode <> 0 Then
    MsgBox "Network Topology Mapper failed to start. Exit code: " & exitCode, vbCritical, "Network Topology Mapper"
End If

WScript.Quit exitCode
