#Requires -Version 5.1
<#
.SYNOPSIS
    Reverses the reversible changes recorded in a ShackCleanup ChangeLog.csv:
    registry/policy values, startup-item disables, scheduled-task disables, service start modes, power settings.

.DESCRIPTION
    Uninstalled software (Office, OneDrive, Teams, Store apps) and winget upgrades can't be undone
    here -- use the restore point (rstrui.exe) or reinstall.
    Use -FindingId to undo only specific findings (the Id column from Findings.csv).

.EXAMPLE
    .\ShackCleanup-Undo.ps1 -ChangeLog C:\ShackCleanup\Report-...\Act-...\ChangeLog.csv -WhatIf
    .\ShackCleanup-Undo.ps1 -ChangeLog ...\ChangeLog.csv -FindingId 12,17
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$ChangeLog,
    [int[]]$FindingId
)

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell window (Run as administrator).'; exit 1
}

$entries = @(Import-Csv $ChangeLog | Where-Object { $_.Reversible -eq 'True' -and $_.Result -eq 'OK' })
if ($FindingId) { $entries = @($entries | Where-Object { [int]$_.FindingId -in $FindingId }) }
[array]::Reverse($entries)
Write-Host "Reversible changes to undo: $($entries.Count)" -ForegroundColor Cyan

function ConvertFrom-HexString { param([string]$Hex) [byte[]]($Hex -split '-' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }) }

foreach ($e in $entries) {
    switch ($e.Kind) {
        { $_ -in 'Registry', 'StartupApproved' } {
            $i = $e.OldValue.IndexOf(':')
            $kind = if ($i -ge 0) { $e.OldValue.Substring(0, $i) } else { '' }
            $val  = if ($i -ge 0) { $e.OldValue.Substring($i + 1) } else { $e.OldValue }
            if ($val -eq '<absent>' -or [string]::IsNullOrEmpty($kind)) {
                if ($PSCmdlet.ShouldProcess("$($e.Target)\$($e.Property)", 'Remove value (did not exist before)')) {
                    Remove-ItemProperty -Path $e.Target -Name $e.Property -ErrorAction SilentlyContinue
                    Write-Host "   removed  $($e.Target)\$($e.Property)"
                }
            } else {
                $typed = switch ($kind) {
                    'DWord'       { [int]$val }
                    'QWord'       { [long]$val }
                    'Binary'      { ConvertFrom-HexString $val }
                    'MultiString' { [string[]]($val -split "`n") }
                    default       { $val }
                }
                if ($PSCmdlet.ShouldProcess("$($e.Target)\$($e.Property)", "Restore $kind = $val")) {
                    New-ItemProperty -Path $e.Target -Name $e.Property -PropertyType $kind -Value $typed -Force | Out-Null
                    Write-Host "   restored $($e.Target)\$($e.Property) = $val"
                }
            }
        }
        'ScheduledTask' {
            $tp, $tn = $e.Target -split '\|', 2
            if ($e.OldValue -ne 'Disabled' -and $PSCmdlet.ShouldProcess("$tp$tn", 'Enable scheduled task')) {
                Enable-ScheduledTask -TaskPath $tp -TaskName $tn -ErrorAction SilentlyContinue | Out-Null
                Write-Host "   enabled  task $tp$tn"
            }
        }
        'Service' {
            if ($PSCmdlet.ShouldProcess($e.Target, "Set start mode back to $($e.OldValue)")) {
                switch ($e.OldValue) {
                    'AutomaticDelayed' { & sc.exe config $e.Target start= delayed-auto | Out-Null }
                    'Automatic'        { Set-Service -Name $e.Target -StartupType Automatic }
                    'Manual'           { Set-Service -Name $e.Target -StartupType Manual }
                    default            { Set-Service -Name $e.Target -StartupType $e.OldValue -ErrorAction SilentlyContinue }
                }
                if ($e.OldValue -like 'Automatic*') { Start-Service -Name $e.Target -ErrorAction SilentlyContinue }
                Write-Host "   service  $($e.Target) -> $($e.OldValue)"
            }
        }
        'PowerCfg' {
            $sub, $set = $e.Target -split '\|'
            $ac, $dc = $e.OldValue -split '\|'
            if ($PSCmdlet.ShouldProcess($e.Target, "powercfg AC=$ac DC=$dc")) {
                if ($ac -ne '') { & powercfg /setacvalueindex SCHEME_CURRENT $sub $set $ac | Out-Null }
                if ($dc -ne '') { & powercfg /setdcvalueindex SCHEME_CURRENT $sub $set $dc | Out-Null }
                & powercfg /setactive SCHEME_CURRENT | Out-Null
                Write-Host "   powercfg $($e.Target) AC=$ac DC=$dc"
            }
        }
    }
}

$notUndoable = @(Import-Csv $ChangeLog | Where-Object { $_.Reversible -eq 'False' -and $_.Result -like 'OK*' })
if ($notUndoable) {
    Write-Host ''
    Write-Host "$($notUndoable.Count) change(s) can't be undone by this script (uninstalls/upgrades). Use rstrui.exe and pick the 'ShackCleanup' restore point if needed." -ForegroundColor Yellow
}
Write-Host 'Done. Reboot to make sure everything takes effect.'
