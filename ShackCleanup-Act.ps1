#Requires -Version 5.1
<#
.SYNOPSIS
    Applies the actions you chose in Findings.csv (from ShackCleanup-Report.ps1).

.DESCRIPTION
    Only rows whose Action column is Disable, Remove, Apply, or Upgrade are touched.
    Blank Action = leave alone. Order of operations:
        0. System restore point (+ registry exports of every key it may change)
        1. Disable non-Office startup items, scheduled tasks, services
        2. Stop Office / OneDrive / Teams processes
        3. Uninstall Office Click-to-Run, MSI, Teams, OneDrive, other Office365 entries
        4. Remove Office365 Store (AppX) apps, for all users and the provisioning image
        5. Disable any Office365 tasks/services the uninstallers left behind
        6. Registry / policy / power settings (telemetry -> Required only, block OneDrive/Teams reinstall)
        7. winget upgrades for the rows marked Upgrade
    Every reversible change (registry, startup, task, service, power) is written to ChangeLog.csv,
    which ShackCleanup-Undo.ps1 uses to put things back. Uninstalls are not reversible except via
    the restore point.

.PARAMETER FindingsCsv  Path to Findings.csv from the report.
.PARAMETER WhatIf       Dry run: shows everything it would do, changes nothing.
.PARAMETER Yes          Skip the "type YES" confirmation.
.PARAMETER Force        Remove OneDrive even if Known Folder Move is active (not recommended).
.PARAMETER SkipRestorePoint  Continue even if a restore point can't be created (not recommended).

.EXAMPLE
    .\ShackCleanup-Act.ps1 -FindingsCsv C:\ShackCleanup\Report-20261111-070000\Findings.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$FindingsCsv,
    [switch]$Yes,
    [switch]$Force,
    [switch]$SkipRestorePoint
)

$ErrorActionPreference = 'Continue'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell window (Run as administrator).'; exit 1
}
if (-not (Test-Path $FindingsCsv)) { Write-Error "Not found: $FindingsCsv"; exit 1 }

$dry    = [bool]$WhatIfPreference
# Pre-load modules with WhatIf off; otherwise -WhatIf leaks into their alias setup and prints noise
$savedWhatIf = $WhatIfPreference; $WhatIfPreference = $false
Import-Module CimCmdlets, ScheduledTasks, Appx -ErrorAction SilentlyContinue
$WhatIfPreference = $savedWhatIf
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = Join-Path (Split-Path $FindingsCsv -Parent) $(if ($dry) { "WhatIf-$stamp" } else { "Act-$stamp" })
New-Item -ItemType Directory -Path $OutDir -Force -WhatIf:$false | Out-Null
Start-Transcript -Path (Join-Path $OutDir 'Transcript.txt') -WhatIf:$false | Out-Null

$rows = @(Import-Csv $FindingsCsv | Where-Object { $_.Action -in 'Disable', 'Remove', 'Apply', 'Upgrade' })
if ($rows.Count -eq 0) { Write-Host 'No rows with an Action of Disable/Remove/Apply/Upgrade. Nothing to do.'; try { Stop-Transcript | Out-Null } catch {}; exit 0 }

Write-Host "Rows selected for action: $($rows.Count)" -ForegroundColor Cyan
$rows | Group-Object Category, Type, Action | Sort-Object Name | Format-Table @{ n = 'Category, Type, Action'; e = { $_.Name } }, Count -AutoSize | Out-String | Write-Host

$kfmBlock = Import-Csv $FindingsCsv | Where-Object { $_.Type -eq 'Check' -and $_.Flag -eq 'Blocker' }
if ($kfmBlock -and -not $Force) {
    Write-Warning 'OneDrive Known Folder Move is active - OneDrive will NOT be uninstalled this run (use -Force to override).'
}

if (-not $dry -and -not $Yes) {
    $ans = Read-Host 'Type YES to proceed'
    if ($ans -cne 'YES') { Write-Host 'Aborted.'; try { Stop-Transcript | Out-Null } catch {}; exit 0 }
}

# ---------------------------------------------------------------- change log
$ChangeLog = Join-Path $OutDir 'ChangeLog.csv'
$script:Log = New-Object System.Collections.Generic.List[object]
$script:Handled = New-Object 'System.Collections.Generic.HashSet[string]'
function Write-Change {
    param($FindingId, $Kind, $Target, $Property = '', $OldValue = '', $NewValue = '', $Result = 'OK', $Reversible = $true)
    $script:Log.Add([pscustomobject][ordered]@{
        Time = (Get-Date -Format s); FindingId = $FindingId; Kind = $Kind; Target = $Target; Property = $Property
        OldValue = $OldValue; NewValue = $NewValue; Result = $Result; Reversible = $Reversible
    })
    if ($FindingId) { [void]$script:Handled.Add("$FindingId") }
    $script:Log | Export-Csv $ChangeLog -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $color = if ($Result -like 'OK*' -or $Result -eq 'WhatIf') { 'Gray' } else { 'Yellow' }
    Write-Host ("   [{0}] {1} {2} {3} -> {4}" -f $Result, $Kind, $Target, $Property, $NewValue) -ForegroundColor $color
}

function ConvertTo-HexString { param([byte[]]$Bytes) ($Bytes | ForEach-Object { $_.ToString('X2') }) -join '-' }

function Get-RegState {
    param($Path, $Name)
    try {
        $item = Get-Item -Path $Path -ErrorAction Stop
        if ($item.GetValueNames() -notcontains $Name) { return @{ Exists = $false; Kind = ''; Value = '<absent>' } }
        $kind = $item.GetValueKind($Name).ToString()
        $val  = $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
        if ($kind -eq 'Binary') { $val = ConvertTo-HexString $val }
        elseif ($kind -eq 'MultiString') { $val = $val -join "`n" }
        return @{ Exists = $true; Kind = $kind; Value = "$val" }
    } catch { return @{ Exists = $false; Kind = ''; Value = '<absent>' } }
}

function Set-LoggedRegistry {
    param($FindingId, $Path, $Name, [ValidateSet('DWord', 'Binary', 'String')]$Type, $Value, $Kind = 'Registry')
    $old = Get-RegState $Path $Name
    $newDisplay = if ($Type -eq 'Binary') { ConvertTo-HexString $Value } else { "$Value" }
    if ($old.Exists -and $old.Value -eq $newDisplay) { Write-Change $FindingId $Kind $Path $Name $old.Value $newDisplay 'OK (already set)'; return }
    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set $Type = $newDisplay")) {
        try {
            if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
            New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force -ErrorAction Stop | Out-Null
            Write-Change $FindingId $Kind $Path $Name "$($old.Kind):$($old.Value)" "$($Type):$newDisplay"
        } catch { Write-Change $FindingId $Kind $Path $Name $old.Value $newDisplay "FAILED: $($_.Exception.Message)" }
    } else { Write-Change $FindingId $Kind $Path $Name $old.Value $newDisplay 'WhatIf' }
}

# ---------------------------------------------------------------- 0. restore point + registry backups
if (-not $dry) {
    Write-Host '[0] Creating system restore point...' -ForegroundColor Cyan
    $rpOk = $false
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        $srKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $oldFreq = (Get-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
        New-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -PropertyType DWord -Value 0 -Force | Out-Null   # bypass 24 h limit
        $before = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count
        Checkpoint-Computer -Description "ShackCleanup $stamp" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $rpOk = (@(Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count -gt $before)
        if ($null -eq $oldFreq) { Remove-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue }
        else { Set-ItemProperty $srKey -Name SystemRestorePointCreationFrequency -Value $oldFreq }
    } catch { Write-Warning "Restore point failed: $($_.Exception.Message)" }
    if ($rpOk) { Write-Host '   Restore point created.' -ForegroundColor Green }
    elseif (-not $SkipRestorePoint) { Write-Error 'Could not confirm a new restore point. Fix System Protection (sysdm.cpl > System Protection) or re-run with -SkipRestorePoint.'; try { Stop-Transcript | Out-Null } catch {}; exit 1 }

    $regBackup = Join-Path $OutDir 'RegistryBackup'
    New-Item -ItemType Directory $regBackup -Force | Out-Null
    $keys = @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved', 'HKLM\SOFTWARE\Policies', 'HKCU\Software\Policies',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy',
        'HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
    )
    $n = 0
    foreach ($k in $keys) { $n++; & reg.exe export $k (Join-Path $regBackup ("{0:D2}.reg" -f $n)) /y 2>$null | Out-Null }
    Write-Host "   Registry exported to $regBackup"
}

# ---------------------------------------------------------------- helpers
$approvedMap = @{
    'HKLM-Run'           = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKLM-Run32'         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    'HKCU-Run'           = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKCU-StartupFolder' = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    'HKLM-StartupFolder' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
}
$DisabledBytes = [byte[]](3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)   # same value Task Manager writes when you click Disable

function Disable-StartupItem {
    param($Row)
    $path = $approvedMap[$Row.Location]
    if (-not $path) { Write-Change $Row.Id 'Startup' $Row.Name '' '' '' "FAILED: unknown location $($Row.Location)" $false; return }
    Set-LoggedRegistry -FindingId $Row.Id -Path $path -Name $Row.ItemName -Type Binary -Value $DisabledBytes -Kind 'StartupApproved'
}

function Disable-TaskRow {
    param($Row)
    $t = Get-ScheduledTask -TaskPath $Row.Location -TaskName $Row.ItemName -ErrorAction SilentlyContinue
    if (-not $t) { Write-Change $Row.Id 'ScheduledTask' $Row.Name 'State' '' 'Disabled' 'OK (not present)' $false; return }
    if ($t.State -eq 'Disabled') { Write-Change $Row.Id 'ScheduledTask' $Row.Name 'State' 'Disabled' 'Disabled' 'OK (already)'; return }
    if ($PSCmdlet.ShouldProcess($Row.Name, 'Disable scheduled task')) {
        try { $t | Disable-ScheduledTask -ErrorAction Stop | Out-Null; Write-Change $Row.Id 'ScheduledTask' "$($Row.Location)|$($Row.ItemName)" 'State' $t.State 'Disabled' }
        catch { Write-Change $Row.Id 'ScheduledTask' $Row.Name 'State' $t.State 'Disabled' "FAILED: $($_.Exception.Message)" }
    } else { Write-Change $Row.Id 'ScheduledTask' $Row.Name 'State' $t.State 'Disabled' 'WhatIf' }
}

function Disable-ServiceRow {
    param($Row)
    $s = Get-CimInstance Win32_Service -Filter "Name='$($Row.ItemName)'" -ErrorAction SilentlyContinue
    if (-not $s) { Write-Change $Row.Id 'Service' $Row.ItemName 'StartMode' '' 'Disabled' 'OK (not present)' $false; return }
    $old = if ($s.StartMode -eq 'Auto' -and $s.DelayedAutoStart) { 'AutomaticDelayed' } elseif ($s.StartMode -eq 'Auto') { 'Automatic' } else { $s.StartMode }
    if ($old -eq 'Disabled') { Write-Change $Row.Id 'Service' $Row.ItemName 'StartMode' $old 'Disabled' 'OK (already)'; return }
    if ($PSCmdlet.ShouldProcess($Row.ItemName, "Stop and disable service (was $old)")) {
        try {
            Stop-Service -Name $Row.ItemName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $Row.ItemName -StartupType Disabled -ErrorAction Stop
            Write-Change $Row.Id 'Service' $Row.ItemName 'StartMode' $old 'Disabled'
        } catch { Write-Change $Row.Id 'Service' $Row.ItemName 'StartMode' $old 'Disabled' "FAILED: $($_.Exception.Message)" }
    } else { Write-Change $Row.Id 'Service' $Row.ItemName 'StartMode' $old 'Disabled' 'WhatIf' }
}

function Split-Command {
    param([string]$Cmd)
    $c = $Cmd.Trim()
    if ($c -match '^"([^"]+)"\s*(.*)$') { return @($Matches[1], $Matches[2]) }
    if ($c -match '^(.+?\.exe)\s*(.*)$') { return @($Matches[1], $Matches[2]) }
    return @($c, '')
}

function Invoke-Uninstall {
    param($Row, [string]$Exe, [string]$ArgList, [int]$TimeoutMin = 30)
    if (-not $PSCmdlet.ShouldProcess($Row.Name, "Uninstall: `"$Exe`" $ArgList")) { Write-Change $Row.Id 'Uninstall' $Row.Name '' '' "$Exe $ArgList" 'WhatIf' $false; return }
    try {
        $sp = @{ FilePath = $Exe; PassThru = $true; WindowStyle = 'Hidden'; ErrorAction = 'Stop' }
        if (-not [string]::IsNullOrWhiteSpace($ArgList)) { $sp.ArgumentList = $ArgList.Trim() }
        $p = Start-Process @sp
        if (-not $p.WaitForExit($TimeoutMin * 60 * 1000)) { Write-Change $Row.Id 'Uninstall' $Row.Name '' '' 'timed out' "FAILED: still running after $TimeoutMin min" $false; return }
        $result = if ($p.ExitCode -in 0, 3010, 1605) { "OK (exit $($p.ExitCode))" } else { "CHECK (exit $($p.ExitCode))" }
        Write-Change $Row.Id 'Uninstall' $Row.Name '' $Row.State 'removed' $result $false
    } catch { Write-Change $Row.Id 'Uninstall' $Row.Name '' '' '' "FAILED: $($_.Exception.Message)" $false }
}

# ---------------------------------------------------------------- 1. startup / tasks / services (non-Office)
Write-Host '[1] Startup items, scheduled tasks, services...' -ForegroundColor Cyan
foreach ($r in $rows | Where-Object { $_.Action -eq 'Disable' }) {
    switch ($r.Type) {
        { $_ -in 'RunKey', 'StartupFolder' } { Disable-StartupItem $r }
        'ScheduledTask' { Disable-TaskRow $r }
        'Service'       { Disable-ServiceRow $r }
    }
}

# ---------------------------------------------------------------- 2. stop Office-family processes
$o365Rows = @($rows | Where-Object { $_.Category -eq 'Office365' -and $_.Action -eq 'Remove' })
if ($o365Rows.Count -gt 0) {
    Write-Host '[2] Stopping Office / OneDrive / Teams processes...' -ForegroundColor Cyan
    $names = 'WINWORD', 'EXCEL', 'POWERPNT', 'OUTLOOK', 'ONENOTE', 'MSACCESS', 'MSPUB', 'lync', 'OneDrive', 'Teams', 'ms-teams', 'Skype'
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            if ($PSCmdlet.ShouldProcess("$($_.ProcessName) ($($_.Id))", 'Stop process')) { $_ | Stop-Process -Force -ErrorAction SilentlyContinue }
        }
    }
}

# ---------------------------------------------------------------- 3. uninstalls
if ($o365Rows.Count -gt 0) { Write-Host '[3] Uninstalling Office 365 / OneDrive / Teams...' -ForegroundColor Cyan }

# 3a. Click-to-Run (Microsoft 365 Apps). Main product first; language packs usually disappear with it.
foreach ($r in $o365Rows | Where-Object Type -eq 'Uninstall-C2R' | Sort-Object { $_.Name -match ' - [a-z]{2}-[a-z]{2}$' }) {
    if (-not (Test-Path $r.Location)) { Write-Change $r.Id 'Uninstall' $r.Name '' '' '' 'OK (already gone)' $false; continue }
    $parts = Split-Command $r.Detail
    $arg = $parts[1]
    if ($arg -notmatch 'DisplayLevel=') { $arg = "$arg DisplayLevel=False" }
    Invoke-Uninstall $r $parts[0] $arg 45
    if (-not $dry) {   # OfficeClickToRun can hand off to the service; wait for the ARP entry to vanish
        $deadline = (Get-Date).AddMinutes(30)
        while ((Test-Path $r.Location) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 15 }
        if (Test-Path $r.Location) { Write-Warning "   $($r.Name) still listed after 30 min - check Apps & features." }
    }
}

# 3b. MSI-based (Teams Machine-Wide Installer, Teams Meeting Add-in, older Office bits)
foreach ($r in $o365Rows | Where-Object Type -eq 'Uninstall-MSI') {
    if (-not (Test-Path $r.Location)) { Write-Change $r.Id 'Uninstall' $r.Name '' '' '' 'OK (already gone)' $false; continue }
    $code = $r.ItemName
    if ($code -notmatch '^\{[0-9A-Fa-f\-]{36}\}$' -and $r.Detail -match '(\{[0-9A-Fa-f\-]{36}\})') { $code = $Matches[1] }
    Invoke-Uninstall $r "$env:SystemRoot\System32\msiexec.exe" "/x $code /qn /norestart"
}

# 3c. Teams classic (per-user Squirrel install)
foreach ($r in $o365Rows | Where-Object Type -eq 'Uninstall-TeamsClassic') {
    $upd = Join-Path $env:LOCALAPPDATA 'Microsoft\Teams\Update.exe'
    if (Test-Path $upd) { Invoke-Uninstall $r $upd '--uninstall -s' }
    else { $parts = Split-Command $r.Detail; Invoke-Uninstall $r $parts[0] "$($parts[1]) -s" }
}

# 3d. OneDrive
foreach ($r in $o365Rows | Where-Object Type -eq 'Uninstall-OneDrive') {
    if ($kfmBlock -and -not $Force) { Write-Change $r.Id 'Uninstall' $r.Name '' '' '' 'SKIPPED: Known Folder Move active' $false; continue }
    $parts = Split-Command $r.Detail
    $exe = $parts[0]
    if (-not (Test-Path $exe)) {
        $exe = @("$env:SystemRoot\SysWOW64\OneDriveSetup.exe", "$env:SystemRoot\System32\OneDriveSetup.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    }
    $odArgs = if ($parts[1] -match '(?i)/uninstall') { $parts[1] } else { '/uninstall' }
    if ($exe -like "$env:ProgramFiles*" -and $odArgs -notmatch '(?i)/allusers') { $odArgs = "$odArgs /allusers" }   # per-machine install
    if ($exe) { Invoke-Uninstall $r $exe $odArgs }
    else { Write-Change $r.Id 'Uninstall' $r.Name '' '' '' 'FAILED: OneDriveSetup.exe not found' $false }
}

# 3e. Anything else (Skype classic, add-ins with their own uninstaller)
foreach ($r in $o365Rows | Where-Object Type -eq 'Uninstall-Exe') {
    if (-not (Test-Path $r.Location)) { Write-Change $r.Id 'Uninstall' $r.Name '' '' '' 'OK (already gone)' $false; continue }
    $parts = Split-Command $r.Detail
    $arg = $parts[1]
    if ($parts[0] -match '(?i)unins\d+\.exe$' -and $arg -notmatch '(?i)silent') { $arg = "$arg /VERYSILENT /NORESTART" }
    Invoke-Uninstall $r $parts[0] $arg
}

# ---------------------------------------------------------------- 4. AppX
$appxRows = @($rows | Where-Object { $_.Type -eq 'Appx' -and $_.Action -eq 'Remove' })
if ($appxRows.Count -gt 0) { Write-Host '[4] Removing Store apps...' -ForegroundColor Cyan }
foreach ($r in $appxRows) {
    if (-not $PSCmdlet.ShouldProcess($r.ItemName, 'Remove AppX package (all users + provisioned)')) { Write-Change $r.Id 'Appx' $r.ItemName '' $r.State 'removed' 'WhatIf' $false; continue }
    $errs = @()
    foreach ($pkg in @(Get-AppxPackage -AllUsers -Name $r.ItemName -ErrorAction SilentlyContinue)) {
        try { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop } catch { $errs += $_.Exception.Message }
    }
    foreach ($pp in @(Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq $r.ItemName)) {
        try { Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null } catch { $errs += $_.Exception.Message }
    }
    $res = if ($errs) { "CHECK: $($errs -join ' / ')" } else { 'OK' }
    Write-Change $r.Id 'Appx' $r.ItemName '' $r.State 'removed' $res $false
}

# ---------------------------------------------------------------- 5. Office leftovers
$leftRows = @($o365Rows | Where-Object { $_.Type -in 'ScheduledTask', 'Service' })
if ($leftRows.Count -gt 0) { Write-Host '[5] Disabling Office tasks/services the uninstallers left behind...' -ForegroundColor Cyan }
foreach ($r in $leftRows) {
    if ($r.Type -eq 'ScheduledTask') { Disable-TaskRow $r } else { Disable-ServiceRow $r }
}
foreach ($r in $o365Rows | Where-Object { $_.Type -in 'RunKey', 'StartupFolder' }) { Disable-StartupItem $r }

# ---------------------------------------------------------------- 6. registry / policy / power
$regRows = @($rows | Where-Object { $_.Action -eq 'Apply' })
if ($regRows.Count -gt 0) { Write-Host '[6] Registry, policy, and power settings...' -ForegroundColor Cyan }
foreach ($r in $regRows) {
    switch ($r.Type) {
        'Registry' {
            $p = $r.Detail -split '\|'
            if ($p.Count -ne 4 -or $p[0] -notmatch '^HK(LM|CU):\\') { Write-Change $r.Id 'Registry' $r.Name '' '' '' 'FAILED: bad Detail format - re-run the report (v1.0.1+) to regenerate Findings.csv' $false; continue }
            Set-LoggedRegistry -FindingId $r.Id -Path $p[0] -Name $p[1] -Type $p[2] -Value ([int]$p[3])
        }
        'PowerCfg' {
            $p = $r.Detail -split '\|'   # subgroup|setting|value
            $q = powercfg /q SCHEME_CURRENT $p[0] $p[1] 2>$null
            $old = ($q | Select-String 'Current AC Power Setting Index:\s*0x([0-9a-f]+)').Matches | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) } | Select-Object -First 1
            $oldDc = ($q | Select-String 'Current DC Power Setting Index:\s*0x([0-9a-f]+)').Matches | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) } | Select-Object -First 1
            if ($PSCmdlet.ShouldProcess($r.Name, "powercfg set AC/DC = $($p[2])")) {
                & powercfg /setacvalueindex SCHEME_CURRENT $p[0] $p[1] $p[2] | Out-Null
                if ($null -ne $oldDc) { & powercfg /setdcvalueindex SCHEME_CURRENT $p[0] $p[1] $p[2] | Out-Null }
                & powercfg /setactive SCHEME_CURRENT | Out-Null
                Write-Change $r.Id 'PowerCfg' "$($p[0])|$($p[1])" 'AC|DC' "$old|$oldDc" "$($p[2])|$($p[2])"
            } else { Write-Change $r.Id 'PowerCfg' $r.Name 'AC|DC' "$old|$oldDc" $p[2] 'WhatIf' }
        }
    }
}

# ---------------------------------------------------------------- 7. winget removals and upgrades
$wgRemove = @($rows | Where-Object { $_.Type -eq 'Winget' -and $_.Action -eq 'Remove' })
$wgUpdate = @($rows | Where-Object { $_.Type -eq 'Winget' -and $_.Action -eq 'Upgrade' })
if ($wgRemove.Count + $wgUpdate.Count -gt 0) {
    Write-Host '[7] Third-party software (winget)...' -ForegroundColor Cyan
    $winget = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if (-not $winget) {
        $winget = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
                  Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $winget) {
        Write-Warning 'winget.exe not found - skipping. Install/update "App Installer" from the Microsoft Store.'
        foreach ($r in $wgRemove + $wgUpdate) { Write-Change $r.Id 'Winget' $r.ItemName '' '' $r.Action 'FAILED: winget.exe not found' $false }
    } else {
        foreach ($r in $wgRemove) {
            if ($PSCmdlet.ShouldProcess("$($r.Name) [$($r.ItemName)]", 'winget uninstall')) {
                Write-Host "   Uninstalling $($r.Name)..."
                & $winget uninstall --id $r.ItemName --exact --silent --accept-source-agreements --disable-interactivity | Out-Host
                $code = $LASTEXITCODE
                Write-Change $r.Id 'Winget' $r.ItemName 'Installed' $r.Detail 'uninstalled' $(if ($code -eq 0) { 'OK' } else { "CHECK (exit $code)" }) $false
            } else { Write-Change $r.Id 'Winget' $r.ItemName 'Installed' $r.Detail 'uninstall' 'WhatIf' $false }
        }
        foreach ($r in $wgUpdate) {
            if ($PSCmdlet.ShouldProcess("$($r.Name) [$($r.ItemName)]", "winget upgrade $($r.Detail)")) {
                Write-Host "   Upgrading $($r.Name) ($($r.Detail))..."
                & $winget upgrade --id $r.ItemName --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity | Out-Host
                $code = $LASTEXITCODE
                Write-Change $r.Id 'Winget' $r.ItemName 'Version' $r.Detail 'upgraded' $(if ($code -eq 0) { 'OK' } else { "CHECK (exit $code)" }) $false
            } else { Write-Change $r.Id 'Winget' $r.ItemName 'Version' $r.Detail 'upgrade' 'WhatIf' $false }
        }
    }
}

# ---------------------------------------------------------------- unhandled rows (never silently ignore an instruction)
$unhandled = @($rows | Where-Object { -not $script:Handled.Contains("$($_.Id)") })
if ($kfmBlock -and -not $Force) { $unhandled = @($unhandled | Where-Object { $_.Type -ne 'Uninstall-OneDrive' }) }
if ($unhandled.Count -gt 0) {
    Write-Host ''
    Write-Warning "$($unhandled.Count) selected row(s) were NOT acted on - this Type/Action combination isn't supported:"
    $unhandled | Format-Table Id, Category, Type, Action, Name -AutoSize | Out-String | Write-Host
    foreach ($r in $unhandled) { [void]$script:Handled.Add("$($r.Id)"); $script:Log.Add([pscustomobject][ordered]@{
        Time = (Get-Date -Format s); FindingId = $r.Id; Kind = $r.Type; Target = $r.Name; Property = ''; OldValue = ''
        NewValue = $r.Action; Result = 'NOT HANDLED: unsupported Type/Action'; Reversible = $false }) }
    $script:Log | Export-Csv $ChangeLog -NoTypeInformation -Encoding UTF8 -WhatIf:$false
}

# ---------------------------------------------------------------- done
Write-Host ''
Write-Host '================ DONE ================' -ForegroundColor Green
$script:Log | Group-Object { ($_.Result -split '[ :(]')[0] } | Format-Table @{ n = 'Result'; e = { $_.Name } }, Count -AutoSize | Out-String | Write-Host
Write-Host "Change log : $ChangeLog"
Write-Host "Transcript : $(Join-Path $OutDir 'Transcript.txt')"
if (-not $dry) {
    Write-Host ''
    Write-Host 'Reboot, then re-run ShackCleanup-Report.ps1 to confirm everything is gone.' -ForegroundColor Yellow
    Write-Host "To reverse registry/startup/task/service changes: .\ShackCleanup-Undo.ps1 -ChangeLog `"$ChangeLog`"" -ForegroundColor Yellow
}
# Stop-Transcript has no -WhatIf in Windows PowerShell 5.1, so no -WhatIf:$false here
try { Stop-Transcript | Out-Null } catch {}
