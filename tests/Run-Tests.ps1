#Requires -Version 5.1
<#
.SYNOPSIS
    Offline tests for the ShackCleanup scripts. Runs on Windows PowerShell 5.1 or PowerShell 7,
    on any OS: Windows-only cmdlets are replaced with stubs. Changes nothing.
.EXAMPLE
    powershell -NoProfile -File .\tests\Run-Tests.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$script:Fail = 0; $script:Pass = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Pass++; Write-Host "  PASS  $Message" }
    else { $script:Fail++; Write-Host "  FAIL  $Message" -ForegroundColor Red }
}
function Get-Section {
    param([string]$Source, [string]$From, [string]$To)
    $a = $Source.IndexOf($From); $b = $Source.IndexOf($To)
    if ($a -lt 0 -or $b -le $a) { throw "Section not found: '$From' .. '$To'" }
    return $Source.Substring($a, $b - $a)
}

Write-Host 'Parse check'
foreach ($f in Get-ChildItem -Path $root -Filter *.ps1) {
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$t, [ref]$e)
    Assert-True ($e.Count -eq 0) "$($f.Name) parses ($($e.Count) errors)"
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    Assert-True (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) "$($f.Name) is ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI)"
}

$src = Get-Content (Join-Path $root 'ShackCleanup-Report.ps1') -Raw
Invoke-Expression (Get-Section $src '$Findings = New-Object' '# ---------------------------------------------------------------- 1. hardware')

# Stubs: nothing is set in the registry, Edge is installed
function Get-ItemProperty { param($Path, $Name) throw 'absent' }
function Test-Path { param($Path) return ("$Path" -like '*msedge.exe') }

function Test-RegistryRows {
    param([string]$Label)
    $rows = @($Findings | Where-Object Type -eq 'Registry')
    $bad = @($rows | Where-Object { $p = "$($_.Detail)" -split '\|'; $p.Count -ne 4 -or $p[0] -notmatch '^HK(LM|CU):\\' -or $p[2] -ne 'DWord' -or $p[3] -notmatch '^\d+$' })
    Assert-True ($rows.Count -gt 0) "$Label produces registry rows ($($rows.Count))"
    Assert-True ($bad.Count -eq 0) "$Label rows all match the Act script's Path|Name|DWord|Value format (bad: $(($bad | ForEach-Object Name) -join ', '))"
    Assert-True (@($rows | Where-Object { $_.Name.Length -le 1 }).Count -eq 0) "$Label rows have real names, not single characters (v1.0.1 flattening regression)"
}

Write-Host 'Telemetry rows'
$Findings.Clear(); $script:NextId = 1
Invoke-Expression (Get-Section $src '$tel = @(' '# ---------------------------------------------------------------- 7b.')
Test-RegistryRows 'Telemetry'
Assert-True ($Findings.Count -eq 29) "29 telemetry rows (got $($Findings.Count))"

Write-Host 'Telemetry rows on Windows 11'
$Findings.Clear(); $script:NextId = 1; $IsWin11 = $true
Invoke-Expression (Get-Section $src '$tel = @(' '# ---------------------------------------------------------------- 7b.')
Assert-True (@($Findings | Where-Object { $_.Detail -like '*\Windows Feeds|*' }).Count -eq 0) 'Windows 10-only News and Interests row is skipped on Windows 11 (v1.1.1)'
Assert-True ($Findings.Count -eq 28) "28 telemetry rows on Windows 11 (got $($Findings.Count))"
$IsWin11 = $null

Write-Host 'Windows 11 and Edge rows'
$Findings.Clear(); $script:NextId = 1
$IsWin11 = $true; ${env:ProgramFiles(x86)} = 'C:\Program Files (x86)'; $env:ProgramFiles = 'C:\Program Files'
Invoke-Expression (Get-Section $src '# ---------------------------------------------------------------- 7b.' '# ---------------------------------------------------------------- 8. third-party')
Test-RegistryRows 'Windows 11 + Edge'
Assert-True (@($Findings | Where-Object { $_.Detail -like '*\Dsh|*' }).Count -eq 0) 'no Widgets policy row when the Widgets app is not installed (v1.1.1)'
$Findings.Clear(); $script:NextId = 1
$allAppx = @([pscustomobject]@{ Name = 'MicrosoftWindows.Client.WebExperience' })
Invoke-Expression (Get-Section $src '# ---------------------------------------------------------------- 7b.' '# ---------------------------------------------------------------- 8. third-party')
Assert-True (@($Findings | Where-Object { $_.Detail -like '*\Dsh|*' }).Count -eq 1) 'Widgets policy row present when the Widgets app is installed'
Test-RegistryRows 'Windows 11 + Edge (with Widgets)'
$allAppx = @()
foreach ($c in 'Windows11AI', 'Windows11UI', 'Edge') {
    Assert-True (@($Findings | Where-Object Category -eq $c).Count -gt 0) "category $c present"
}
$dupes = @($Findings | Group-Object { ($_.Detail -split '\|')[0..1] -join '|' } | Where-Object Count -gt 1)
Assert-True ($dupes.Count -eq 0) "no registry value is set twice (dupes: $(($dupes | ForEach-Object Name) -join ', '))"
Assert-True (($Findings | Where-Object Name -like '*jump lists*').Recommendation -eq 'Review') 'recent files / jump lists is Review, not Apply'

$Findings.Clear(); $script:NextId = 1; $IsWin11 = $false
Invoke-Expression (Get-Section $src '# ---------------------------------------------------------------- 7b.' '# ---------------------------------------------------------------- 8. third-party')
Assert-True (@($Findings | Where-Object { $_.Category -like 'Windows11*' }).Count -eq 0) 'no Windows 11 rows on Windows 10'
Assert-True (@($Findings | Where-Object Category -eq 'Edge').Count -gt 0) 'Edge rows on Windows 10 too'

Write-Host 'Already-set values become Keep'
$Findings.Clear(); $script:NextId = 1
function Get-ItemProperty { param($Path, $Name) if ($Name -eq 'StartupBoostEnabled') { [pscustomobject]@{ StartupBoostEnabled = 0 } } else { throw 'absent' } }
Invoke-Expression (Get-Section $src '# ---------------------------------------------------------------- 7c.' '# ---------------------------------------------------------------- 8. third-party')
$sb = $Findings | Where-Object Name -like '*startup boost*'
Assert-True ($sb.Recommendation -eq 'Keep' -and $sb.Action -eq '') 'a value already at its target is Keep with a blank Action'

Write-Host 'Store apps'
$Findings.Clear(); $script:NextId = 1
function Get-AppxPackage { @(
    [pscustomobject]@{ Name = 'Microsoft.Copilot'; Version = '1'; NonRemovable = $false }
    [pscustomobject]@{ Name = 'Microsoft.WindowsCalculator'; Version = '1'; NonRemovable = $false }
    [pscustomobject]@{ Name = 'Microsoft.DesktopAppInstaller'; Version = '1'; NonRemovable = $false }
    [pscustomobject]@{ Name = 'Microsoft.WindowsStore'; Version = '1'; NonRemovable = $false }
    [pscustomobject]@{ Name = 'MicrosoftWindows.CrossDevice'; Version = '1'; NonRemovable = $true }
    [pscustomobject]@{ Name = 'Microsoft.ZuneMusic'; Version = '1'; NonRemovable = $false }) }
function Get-AppxProvisionedPackage { @([pscustomobject]@{ DisplayName = 'Clipchamp.Clipchamp' }) }
Invoke-Expression (Get-Section $src '$appx = @(' '# OneDrive Known Folder Move check')
$names = @($Findings | ForEach-Object Name)
foreach ($keep in 'Microsoft.WindowsCalculator', 'Microsoft.DesktopAppInstaller', 'Microsoft.WindowsStore') {
    Assert-True ($names -notcontains $keep) "$keep is never listed"
}
$kept = @('Microsoft.WindowsCalculator', 'Microsoft.WindowsNotepad', 'Microsoft.Paint', 'Microsoft.Windows.Photos', 'Microsoft.ScreenSketch',
          'Microsoft.WindowsTerminal', 'Microsoft.WindowsCamera', 'Microsoft.WindowsSoundRecorder', 'Microsoft.WindowsAlarms',
          'Microsoft.WindowsStore', 'Microsoft.DesktopAppInstaller', 'Microsoft.StorePurchaseApp', 'Microsoft.SecHealthUI')
$listed = @($appx | ForEach-Object { $_.N })
$overlap = @($kept | Where-Object { $k = $_; $listed | Where-Object { $k -like $_ } })
Assert-True ($overlap.Count -eq 0) "keep-list apps are not in the removal list (overlap: $($overlap -join ', '))"
Assert-True (($Findings | Where-Object Name -eq 'Microsoft.Copilot').Action -eq 'Remove') 'Copilot is Remove'
Assert-True (($Findings | Where-Object Name -eq 'Clipchamp.Clipchamp').State -eq 'Provisioned') 'a provisioned-only package is listed'
Assert-True (($Findings | Where-Object Name -eq 'MicrosoftWindows.CrossDevice').Recommendation -eq 'Keep') 'a non-removable package is Keep'
Assert-True (($Findings | Where-Object Name -eq 'Microsoft.ZuneMusic').Action -eq '') 'Media Player is Review (blank Action)'

Write-Host 'Act: a protected registry value is CHECK, not FAILED'
$act = Get-Content (Join-Path $root 'ShackCleanup-Act.ps1') -Raw
$tmp = Join-Path ([IO.Path]::GetTempPath()) 'shackcleanup-act-test.ps1'
$harness = @(
    '[CmdletBinding(SupportsShouldProcess = $true)] param()'
    '$ChangeLog = Join-Path ([IO.Path]::GetTempPath()) ''shackcleanup-test-changelog.csv'''
    '$script:Log = New-Object System.Collections.Generic.List[object]'
    '$script:Handled = New-Object ''System.Collections.Generic.HashSet[string]'''
    (Get-Section $act 'function Write-Change' '# ---------------------------------------------------------------- 0. restore point')
    'function Get-RegState { param($Path, $Name) @{ Exists = $false; Kind = ''''; Value = ''<absent>'' } }'
    'function New-ItemProperty { throw (New-Object System.UnauthorizedAccessException ''Attempted to perform an unauthorized operation.'') }'
    'function New-Item { }'
    'function Test-Path { param($Path) $true }'
    'function Write-Host { }'
    'Set-LoggedRegistry -FindingId 99 -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Dsh'' -Name ''AllowNewsAndInterests'' -Type DWord -Value 0'
    '($script:Log | Select-Object -Last 1).Result'
    'Remove-Item $ChangeLog -ErrorAction SilentlyContinue'
) -join "`n"
Set-Content -Path $tmp -Value $harness -Encoding ASCII
$result = & $tmp
Remove-Item $tmp -ErrorAction SilentlyContinue
Assert-True ("$result" -like 'CHECK: Windows blocks scripts*') "UnauthorizedAccessException is logged as CHECK with an explanation (got: $result)"

Write-Host ''
Write-Host "Passed $script:Pass, failed $script:Fail"
if ($script:Fail -gt 0) { exit 1 }
