#Requires -Version 5.1
<#
.SYNOPSIS
    Shack PC audit -- READ-ONLY. Inventories hardware, Office 365 / OneDrive / Teams remnants,
    startup items, scheduled tasks, services, Windows telemetry settings, outbound connections,
    and pending third-party (winget) updates.

.DESCRIPTION
    Makes no changes to the system, with one exception: if Microsoft's WinGet PowerShell module
    (Microsoft.WinGet.Client) is missing, it is installed for the current user so pending updates
    can be listed reliably. Use -NoModuleInstall to skip that.

    Output folder: <OutRoot>\Report-<timestamp>\
        Findings.csv     <- the file you review/edit; feed it to ShackCleanup-Act.ps1
        Report.html      <- human-readable version of everything
        Hardware.txt     <- hardware + OS summary (CPU/RAM/SSD/BIOS/TPM)
        Connections.csv  <- outbound TCP connections by process
        DnsCache.csv     <- hostnames this PC has looked up recently
        Transcript.txt

    Findings.csv "Action" column is pre-filled with the recommendation when it is
    Disable / Remove / Apply / Upgrade. Rows marked Review/Keep have a blank Action.
    Change Action to whatever you want (or blank it) before running the Act script.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\ShackCleanup-Report.ps1
#>
[CmdletBinding()]
param(
    [string]$OutRoot = 'C:\ShackCleanup',
    [switch]$NoModuleInstall,
    [switch]$SkipConnections,
    [int]$ConnectionSamples = 3
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- prerequisites
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell window (Run as administrator).'
    exit 1
}

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = Join-Path $OutRoot "Report-$stamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Start-Transcript -Path (Join-Path $OutDir 'Transcript.txt') | Out-Null

$consoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
if ($consoleUser -and ($consoleUser -ne $id.Name)) {
    Write-Warning "You are elevated as '$($id.Name)' but '$consoleUser' is logged on at the console."
    Write-Warning 'Per-user items (HKCU startup entries, OneDrive, Teams) will be read from the elevated account, not the console user.'
}

# ---------------------------------------------------------------- classification rules
# Station-critical software: never recommended for removal/disable.
$StationPattern = '(?i)n1mm|omni-?rig|wsjt|jtdx|jtalert|gridtracker|flexradio|smartsdr|\bicom\b|rs-ba1|rs-ms1|ftdi|silabs|silicon lab|cp210|prolific|dxlab|dxkeeper|spotcollector|log4om|ham radio deluxe|\bhrd\b|microham|so2r|otrsp|remoterig|elecraft|yaesu|kenwood|tqsl|trustedqsl|lotw|vspe|com0com|virtual serial|vb-audio|voicemeeter|mmtty|2tone|win-?test|skimmer|meinberg|ntpd|\bntp\b|dimension ?4|bkttimesync|nettime|rumlog|n3fjp|winkey|k1el|fldigi|flrig|dxlog|hdsdr|sdrsharp|sdr console|sdruno|sdr-?radio|pstrotator|\bspid\b|green ?heron|rtkaud|realtek audio'

# Anything tied to Office 365 / OneDrive / Teams / Skype / Outlook.
$O365Pattern = '(?i)clicktorun|click-to-run|officec2r|officeclicktorun|office ?16|microsoft office|microsoft 365|office automatic updates|office feature updates|officetelemetry|office performance monitor|office background|onedrive|\bteams\b|msteams|skype|outlook|onenote|officehub'

# Ordered: first match wins.
$Rules = @(
    @{ P='(?i)microsoftedgeautolaunch';                                   F='Startup';      R='Disable'; N='Edge startup boost/preload - launches Edge in the background at logon' }
    @{ P='(?i)adobearm|adobe.*(update|genuine)|agsservice|adobegc|ccxprocess|acrobat.*update'; F='Updater/PhonesHome'; R='Disable'; N='Adobe updater/licensing check - update Adobe apps manually' }
    @{ P='(?i)googleupdate|googleupdater|google update|chrome.*update';    F='Updater';      R='Keep';    N='Browser security updates - keep' }
    @{ P='(?i)microsoftedgeupdate|edgeupdate|edge update';                 F='Updater';      R='Keep';    N='Browser security updates - keep' }
    @{ P='(?i)mozilla maintenance|firefox.*(update|background)';           F='Updater';      R='Keep';    N='Browser security updates - keep' }
    @{ P='(?i)brave.*update|opera.*(update|assistant)';                    F='Updater';      R='Keep';    N='Browser security updates - keep' }
    @{ P='(?i)esrv|queencreek|systemusagereport|computing improvement|sur qc|intel.*telemetry'; F='PhonesHome'; R='Disable'; N='Intel Computing Improvement Program telemetry' }
    @{ P='(?i)driver ?& ?support assistant|\bdsa(service|updateservice)?\b|intel.*\bdsa\b'; F='Updater/PhonesHome'; R='Disable'; N='Intel DSA polls Intel constantly - run it manually when you want to check drivers' }
    @{ P='(?i)jusched|java.*update|sunjavaupdate';                         F='Updater';      R='Disable'; N='Java updater' }
    @{ P='(?i)nvtelemetry|nvidia telemetry';                               F='PhonesHome';   R='Disable'; N='NVIDIA telemetry' }
    @{ P='(?i)\bzoom|dropbox|spotify|\bsteam|discord|epic games|itunes|apple software update|ccleaner|wallpaper engine'; F='Startup'; R='Disable'; N='Launches at startup and checks in with its vendor - start it when you need it' }
    @{ P='(?i)teamviewer|anydesk|splashtop|rustdesk|chrome remote desktop|parsec|nomachine'; F='RemoteAccess'; R='Review'; N='Remote access - keep if you use it to reach the shack' }
    @{ P='(?i)logitech|lghub|logioptions|razer|corsair|icue|steelseries';  F='Startup';      R='Review';  N='Peripheral helper - phones home for updates; disable if you do not need its features' }
    @{ P='(?i)avast|\bavg\b|mcafee|norton|webroot|kaspersky';              F='Security';     R='Review';  N='Third-party AV - Defender is enough for most stations; review' }
    @{ P='(?i)update|updater|updatetask';                                  F='Updater';      R='Review';  N='Generic updater - decide if you want it running in the background'; G=$true }
    @{ P='(?i)telemetry|ceip|usage ?report|analytics';                     F='PhonesHome';   R='Review';  N='Looks like telemetry - review'; G=$true }
)

function Get-Classification {
    param([string]$Text)
    if ($Text -match $StationPattern) { return [pscustomobject]@{ Flag='StationCritical'; Rec='Keep';   Note='Station software/driver - leave alone'; Matched=$true } }
    if ($Text -match $O365Pattern)    { return [pscustomobject]@{ Flag='O365';            Rec='Remove'; Note='Office 365 / OneDrive / Teams component'; Matched=$true } }
    foreach ($r in $Rules) {
        if ($Text -match $r.P) { return [pscustomobject]@{ Flag=$r.F; Rec=$r.R; Note=$r.N; Matched=(-not $r.G) } }
    }
    return [pscustomobject]@{ Flag='Info'; Rec='Keep'; Note=''; Matched=$false }
}

function Get-ExePath {
    param([string]$Cmd)
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Cmd.Trim()) -replace '^\\\?\?\\', ''
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js|lnk|dll))(\s|,|$)') { return $Matches[1] }
    return ($c -split '\s+')[0]
}

function Get-Company {
    param([string]$Path)
    try {
        if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) { return (Get-Item -LiteralPath $Path).VersionInfo.CompanyName }
    } catch {}
    return ''
}

$Findings = New-Object System.Collections.Generic.List[object]
$script:NextId = 1
function Add-Finding {
    param($Category, $Type, $Name, $Location = '', $ItemName = '', $Detail = '', $Company = '',
          $State = '', $Flag = 'Info', $Recommendation = 'Keep', $Note = '')
    # Already in the target state? Then there's nothing to do - recommend Keep so it doesn't show up as an action.
    if ($Recommendation -eq 'Disable' -and "$State" -match '^Disabled') {
        $Recommendation = 'Keep'
        $Note = (@($Note, 'Already disabled') | Where-Object { $_ }) -join ' - '
    }
    if ($Recommendation -eq 'Apply' -and $Type -eq 'Registry' -and $Detail) {
        $rp  = $Detail -split '\|'
        $cur = try { (Get-ItemProperty -Path $rp[0] -Name $rp[1] -ErrorAction Stop).($rp[1]) } catch { $null }
        if (-not $State) { $State = "current=$(if ($null -eq $cur) { '<not set>' } else { $cur })" }
        if ($null -ne $cur -and "$cur" -eq $rp[3]) { $Recommendation = 'Keep'; $Note = 'Already set' }
    }
    $action = if ($Recommendation -in 'Disable','Remove','Apply','Upgrade') { $Recommendation } else { '' }
    $Findings.Add([pscustomobject][ordered]@{
        Id = $script:NextId; Category = $Category; Type = $Type; Name = $Name; Location = $Location
        ItemName = $ItemName; Detail = $Detail; Company = $Company; State = $State; Flag = $Flag
        Recommendation = $Recommendation; Action = $action; Note = $Note
    })
    $script:NextId++
}

# ---------------------------------------------------------------- 1. hardware & OS
Write-Host '[1/8] Hardware and OS...' -ForegroundColor Cyan
$cs   = Get-CimInstance Win32_ComputerSystem
$bb   = Get-CimInstance Win32_BaseBoard
$bios = Get-CimInstance Win32_BIOS
$cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
$mem  = Get-CimInstance Win32_PhysicalMemory
$memA = Get-CimInstance Win32_PhysicalMemoryArray | Select-Object -First 1
$os   = Get-CimInstance Win32_OperatingSystem
$cv   = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$secureBoot = try { if (Confirm-SecureBootUEFI) { 'On' } else { 'Off' } } catch { 'Not supported / legacy BIOS mode' }
$tpm = try { Get-Tpm -ErrorAction Stop } catch { $null }
$tpmVer = try { (Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion } catch { '' }

$lastHotfix = $null
try { $lastHotfix = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1 } catch {}

$hw = New-Object System.Collections.Generic.List[string]
$hw.Add("Computer model : $($cs.Manufacturer) $($cs.Model)")
$hw.Add("Baseboard      : $($bb.Manufacturer) $($bb.Product) (ver $($bb.Version))")
$hw.Add("BIOS           : $($bios.SMBIOSBIOSVersion)  dated $(if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString('yyyy-MM-dd') })")
$hw.Add("CPU            : $($cpu.Name.Trim())  ($($cpu.NumberOfCores) cores / $($cpu.NumberOfLogicalProcessors) threads, socket '$($cpu.SocketDesignation)')")
$hw.Add(("RAM total      : {0:N1} GB in {1} module(s); board reports {2} slot(s), max {3:N0} GB" -f ($cs.TotalPhysicalMemory/1GB), @($mem).Count, $memA.MemoryDevices, ($memA.MaxCapacityEx/1MB)))
foreach ($m in $mem) {
    $hw.Add(("   - {0}: {1:N0} GB {2} MT/s  {3} {4}" -f $m.DeviceLocator, ($m.Capacity/1GB), $m.ConfiguredClockSpeed, $m.Manufacturer, ("$($m.PartNumber)".Trim())))
}
try {
    foreach ($d in Get-PhysicalDisk) {
        $rel = try { $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { $null }
        $extra = if ($rel) { "wear $($rel.Wear)%  temp $($rel.Temperature)C  power-on hrs $($rel.PowerOnHours)" } else { '' }
        $hw.Add(("Disk           : $($d.FriendlyName)  {0:N0} GB  {1}/{2}  health {3}  {4}" -f ($d.Size/1GB), $d.MediaType, $d.BusType, $d.HealthStatus, $extra))
    }
} catch {}
$hw.Add("OS             : $($os.Caption) $($cv.DisplayVersion) build $($cv.CurrentBuild).$($cv.UBR)  installed $($os.InstallDate.ToString('yyyy-MM-dd'))")
$hw.Add(("Last boot      : $($os.LastBootUpTime)  (uptime {0:N1} days)" -f ((Get-Date) - $os.LastBootUpTime).TotalDays))
$hw.Add("Secure Boot    : $secureBoot")
$hw.Add("TPM            : $(if ($tpm) { "present=$($tpm.TpmPresent) ready=$($tpm.TpmReady) spec=$tpmVer" } else { 'not detected' })")
if ($lastHotfix) {
    $age = [int]((Get-Date) - $lastHotfix.InstalledOn).TotalDays
    $hw.Add("Last Windows update : $($lastHotfix.HotFixID) on $($lastHotfix.InstalledOn.ToString('yyyy-MM-dd')) ($age days ago)")
    if ($age -gt 45) {
        $hw.Add('   !! No Windows update in 45+ days. Windows 10 only gets security patches if the PC is enrolled in')
        $hw.Add('   !! Extended Security Updates (ESU). Check Settings > Update & Security > Windows Update.')
    }
}
$hw | Set-Content (Join-Path $OutDir 'Hardware.txt') -Encoding UTF8
$hw | ForEach-Object { Write-Host "   $_" }

# ---------------------------------------------------------------- 2. station health checks
Write-Host '[2/8] Station health checks...' -ForegroundColor Cyan
$health = New-Object System.Collections.Generic.List[object]
function Add-Health { param($Check, $Value, $Note = ''); $health.Add([pscustomobject]@{ Check = $Check; Value = $Value; Note = $Note }) }

Add-Health 'Active power plan' ((powercfg /getactivescheme) -join ' ')

$usbQ = powercfg /q SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 2>$null
$usbAC = ($usbQ | Select-String 'Current AC Power Setting Index:\s*0x([0-9a-f]+)').Matches | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) } | Select-Object -First 1
if ($null -ne $usbAC) {
    Add-Health 'USB selective suspend (AC)' $(if ($usbAC -eq 1) { 'Enabled' } else { 'Disabled' })
    if ($usbAC -eq 1) {
        Add-Finding -Category 'StationTuning' -Type 'PowerCfg' -Name 'USB selective suspend (AC power)' `
            -Detail '2a737441-1930-4402-8d77-b2bebba308a3|48e6b7a6-50f5-4782-a5d4-53bb8f07e226|0' -State 'Enabled' `
            -Flag 'Stability' -Recommendation 'Apply' -Note 'Turn off: suspended USB ports are a classic cause of CAT/audio codec/serial dropouts'
    }
}

$hiber = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue).HiberbootEnabled
Add-Health 'Fast Startup' $(if ($hiber -eq 1) { 'Enabled' } else { 'Disabled' })
if ($hiber -eq 1) {
    Add-Finding -Category 'StationTuning' -Type 'Registry' -Name 'Fast Startup (hybrid shutdown)' `
        -Detail 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power|HiberbootEnabled|DWord|0' -State 'Enabled' `
        -Flag 'Stability' -Recommendation 'Apply' -Note 'Turn off so USB/serial drivers fully re-initialize on every boot'
}

$w32 = (w32tm /query /status 2>&1) -join ' | '
Add-Health 'Windows time service' $w32 'FT8/FT4/Q65 need < ~1 s error. Meinberg NTP or a GPS source is better than w32time.'

try {
    $ports = Get-PnpDevice -Class Ports -PresentOnly -ErrorAction Stop | Sort-Object FriendlyName
    Add-Health 'COM ports present' (($ports | ForEach-Object { "$($_.FriendlyName) [$($_.Status)]" }) -join '; ')
} catch {}

$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
Add-Health 'Reboot pending' $pending

try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = (Get-Date).AddDays(-14) } -ErrorAction Stop |
          Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 10
    Add-Health 'Top System errors (14 days)' (($ev | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; ') 'Watch for Kernel-Power 41, WHEA, disk, or USB errors'
} catch { Add-Health 'Top System errors (14 days)' 'none' }

# ---------------------------------------------------------------- 3. startup items
Write-Host '[3/8] Startup items...' -ForegroundColor Cyan
$runKeys = @(
    @{ Key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';             Loc = 'HKLM-Run'   }
    @{ Key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Loc = 'HKLM-Run32' }
    @{ Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run';             Loc = 'HKCU-Run'   }
)
$approvedMap = @{
    'HKLM-Run'            = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKLM-Run32'          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
    'HKCU-Run'            = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
    'HKCU-StartupFolder'  = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    'HKLM-StartupFolder'  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
}
function Get-StartupState {
    param($Loc, $Name)
    try {
        $v = (Get-ItemProperty -Path $approvedMap[$Loc] -Name $Name -ErrorAction Stop).$Name
        if ($v -and ($v[0] -band 1)) { return 'Disabled' }
    } catch {}
    return 'Enabled'
}

foreach ($rk in $runKeys) {
    if (-not (Test-Path $rk.Key)) { continue }
    $props = Get-ItemProperty $rk.Key
    foreach ($p in $props.PSObject.Properties) {
        if ($p.Name -like 'PS*') { continue }
        $exe = Get-ExePath $p.Value
        $co  = Get-Company $exe
        $c   = Get-Classification "$($p.Name) $($p.Value) $co"
        if (($co -match 'Microsoft') -and -not $c.Matched) { continue }   # skip stock Windows entries
        $cat = if ($c.Flag -eq 'O365') { 'Office365' } else { 'Startup' }
        $rec = if ($c.Flag -eq 'O365') { 'Disable' } else { $c.Rec }      # uninstall removes it anyway; disabling is harmless
        Add-Finding -Category $cat -Type 'RunKey' -Name $p.Name -Location $rk.Loc -ItemName $p.Name -Detail $p.Value `
            -Company $co -State (Get-StartupState $rk.Loc $p.Name) -Flag $c.Flag -Recommendation $rec -Note $c.Note
    }
}

$shell = New-Object -ComObject WScript.Shell
foreach ($sf in @(@{ Dir = [Environment]::GetFolderPath('Startup'); Loc = 'HKCU-StartupFolder' },
                  @{ Dir = [Environment]::GetFolderPath('CommonStartup'); Loc = 'HKLM-StartupFolder' })) {
    if (-not (Test-Path $sf.Dir)) { continue }
    foreach ($f in Get-ChildItem $sf.Dir -File -ErrorAction SilentlyContinue) {
        if ($f.Name -eq 'desktop.ini') { continue }
        $target = if ($f.Extension -eq '.lnk') { $shell.CreateShortcut($f.FullName).TargetPath } else { $f.FullName }
        $co = Get-Company $target
        $c  = Get-Classification "$($f.Name) $target $co"
        $cat = if ($c.Flag -eq 'O365') { 'Office365' } else { 'Startup' }
        $rec = if ($c.Flag -eq 'O365') { 'Disable' } else { $c.Rec }
        Add-Finding -Category $cat -Type 'StartupFolder' -Name $f.Name -Location $sf.Loc -ItemName $f.Name -Detail $target `
            -Company $co -State (Get-StartupState $sf.Loc $f.Name) -Flag $c.Flag -Recommendation $rec -Note $c.Note
    }
}

# ---------------------------------------------------------------- 4. scheduled tasks
Write-Host '[4/8] Scheduled tasks...' -ForegroundColor Cyan
$WinTelemetryTasks = @(
    '\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'
    '\Microsoft\Windows\Application Experience\ProgramDataUpdater'
    '\Microsoft\Windows\Application Experience\PcaPatchDbTask'
    '\Microsoft\Windows\Customer Experience Improvement Program\Consolidator'
    '\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip'
    '\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask'
    '\Microsoft\Windows\Autochk\Proxy'
    '\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'
    '\Microsoft\Windows\Feedback\Siuf\DmClient'
    '\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload'
    '\Microsoft\Windows\Maps\MapsUpdateTask'
    '\Microsoft\Windows\Maps\MapsToastTask'
)
foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $full = "$($t.TaskPath)$($t.TaskName)"
    $act  = $t.Actions | Select-Object -First 1
    $cmd  = if ($act.Execute) { "$($act.Execute) $($act.Arguments)".Trim() } elseif ($act.ClassId) { "COM handler $($act.ClassId)" } else { '' }

    if ($WinTelemetryTasks -contains $full) {
        Add-Finding -Category 'Telemetry' -Type 'ScheduledTask' -Name $full -Location $t.TaskPath -ItemName $t.TaskName -Detail $cmd `
            -Company 'Microsoft' -State $t.State -Flag 'PhonesHome' -Recommendation 'Disable' -Note 'Windows CEIP/compatibility telemetry - not needed for Required-level diagnostics'
        continue
    }
    $isOfficeTask = $t.TaskPath -like '\Microsoft\Office\*'
    if ($t.TaskPath -like '\Microsoft\*' -and -not $isOfficeTask) { continue }   # stock Windows tasks

    $exe = Get-ExePath $act.Execute
    $co  = Get-Company $exe
    $c   = Get-Classification "$full $cmd $co"
    if (($co -match 'Microsoft') -and -not $c.Matched -and -not $isOfficeTask) { continue }
    if ($isOfficeTask) { $c = [pscustomobject]@{ Flag = 'O365'; Rec = 'Remove'; Note = 'Office scheduled task' } }
    $cat = if ($c.Flag -eq 'O365') { 'Office365' } else { 'ScheduledTask' }
    Add-Finding -Category $cat -Type 'ScheduledTask' -Name $full -Location $t.TaskPath -ItemName $t.TaskName -Detail $cmd `
        -Company $co -State $t.State -Flag $c.Flag -Recommendation $c.Rec -Note $c.Note
}

# ---------------------------------------------------------------- 5. services
Write-Host '[5/8] Services...' -ForegroundColor Cyan
foreach ($s in Get-CimInstance Win32_Service) {
    $exe = Get-ExePath $s.PathName
    $co  = Get-Company $exe
    $start = if ($s.StartMode -eq 'Auto' -and $s.DelayedAutoStart) { 'AutomaticDelayed' } elseif ($s.StartMode -eq 'Auto') { 'Automatic' } else { $s.StartMode }

    if ($s.Name -eq 'DiagTrack') {
        Add-Finding -Category 'Telemetry' -Type 'Service' -Name "$($s.DisplayName) ($($s.Name))" -ItemName $s.Name -Detail $s.PathName -Company $co `
            -State "$start/$($s.State)" -Flag 'PhonesHome' -Recommendation 'Review' `
            -Note 'This service carries Required-level diagnostics. Keep it running if you want "Required only"; disabling it turns off even that.'
        continue
    }
    if ($s.Name -eq 'dmwappushservice') {
        Add-Finding -Category 'Telemetry' -Type 'Service' -Name "$($s.DisplayName) ($($s.Name))" -ItemName $s.Name -Detail $s.PathName -Company $co `
            -State "$start/$($s.State)" -Flag 'PhonesHome' -Recommendation 'Disable' -Note 'WAP push routing for MDM/telemetry - not needed on a standalone PC'
        continue
    }
    $c = Get-Classification "$($s.Name) $($s.DisplayName) $($s.PathName) $co"
    if (($co -match 'Microsoft') -and -not $c.Matched) { continue }
    if ($s.StartMode -eq 'Disabled' -and $c.Flag -ne 'O365') { continue }
    $cat = if ($c.Flag -eq 'O365') { 'Office365' } else { 'Service' }
    Add-Finding -Category $cat -Type 'Service' -Name "$($s.DisplayName) ($($s.Name))" -ItemName $s.Name -Detail $s.PathName -Company $co `
        -State "$start/$($s.State)" -Flag $c.Flag -Recommendation $c.Rec -Note $c.Note
}

# ---------------------------------------------------------------- 6. Office 365 / OneDrive / Teams installs
Write-Host '[6/8] Office 365 / OneDrive / Teams...' -ForegroundColor Cyan
$uninstRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
)
$exclude = '(?i)visual c\+\+|\.net|microsoft edge|update health|gameinput|windows (sdk|driver|software development)'
foreach ($root in $uninstRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($k in Get-ChildItem $root -ErrorAction SilentlyContinue) {
        $p = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
        if (-not $p.DisplayName) { continue }
        if ($p.DisplayName -notmatch $O365Pattern -or $p.DisplayName -match $exclude) { continue }
        $u = "$($p.UninstallString)"
        $kind = switch -Regex ($u) {
            'OfficeClickToRun\.exe' { 'C2R'; break }
            '(?i)msiexec'           { 'MSI'; break }
            '(?i)OneDriveSetup'     { 'OneDrive'; break }
            '(?i)Teams.*Update\.exe' { 'TeamsClassic'; break }
            default                 { 'Exe' }
        }
        $detail = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $u }
        Add-Finding -Category 'Office365' -Type "Uninstall-$kind" -Name $p.DisplayName -Location $k.PSPath -ItemName $k.PSChildName `
            -Detail $detail -Company $p.Publisher -State "v$($p.DisplayVersion)" -Flag 'O365' -Recommendation 'Remove' -Note 'Uninstall'
    }
}

# Store (AppX) apps tied to Microsoft accounts / Office 365
$appx = @(
    @{ N = 'Microsoft.MicrosoftOfficeHub';         R = 'Remove'; Note = 'Microsoft 365 (Office) hub app' }
    @{ N = 'Microsoft.Office.OneNote';             R = 'Remove'; Note = 'OneNote for Windows 10' }
    @{ N = 'Microsoft.Office.Desktop*';            R = 'Remove'; Note = 'Store-packaged Office' }
    @{ N = 'Microsoft.OutlookForWindows';          R = 'Remove'; Note = 'New Outlook' }
    @{ N = 'MSTeams';                              R = 'Remove'; Note = 'New Teams' }
    @{ N = 'MicrosoftTeams';                       R = 'Remove'; Note = 'Teams (consumer)' }
    @{ N = 'Microsoft.SkypeApp';                   R = 'Remove'; Note = 'Skype (retired)' }
    @{ N = 'Microsoft.windowscommunicationsapps';  R = 'Remove'; Note = 'Mail and Calendar (retired, Microsoft-account/O365 linked)' }
    @{ N = 'Microsoft.Todos';                      R = 'Review'; Note = 'Microsoft To Do - syncs with Microsoft account' }
    @{ N = 'Microsoft.People';                     R = 'Review'; Note = 'People - syncs with Microsoft account' }
    @{ N = 'Microsoft.BingNews';                   R = 'Review'; Note = 'Phones home for content' }
    @{ N = 'Microsoft.BingWeather';                R = 'Review'; Note = 'Phones home for content' }
)
$allAppx = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)
$prov    = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
foreach ($a in $appx) {
    $hits  = @($allAppx | Where-Object { $_.Name -like $a.N })
    $phits = @($prov    | Where-Object { $_.DisplayName -like $a.N })
    $names = @(@($hits | ForEach-Object { $_.Name }) + @($phits | ForEach-Object { $_.DisplayName }) | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($n in $names) {
        $ver = ($hits | Where-Object Name -eq $n | Select-Object -First 1).Version
        $st  = @(); if ($hits | Where-Object Name -eq $n) { $st += 'Installed' }; if ($phits | Where-Object DisplayName -eq $n) { $st += 'Provisioned' }
        $cat = if ($a.R -eq 'Remove') { 'Office365' } else { 'Telemetry' }
        Add-Finding -Category $cat -Type 'Appx' -Name $n -ItemName $n -Detail "v$ver" -Company 'Microsoft' -State ($st -join '+') `
            -Flag $(if ($a.R -eq 'Remove') { 'O365' } else { 'PhonesHome' }) -Recommendation $a.R -Note $a.Note
    }
}

# OneDrive Known Folder Move check (blocker for a clean OneDrive removal)
$usf = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction SilentlyContinue
$kfm = @('Desktop', 'Personal', 'My Pictures', '{374DE290-123F-4565-9164-39C4925E467B}') |
       Where-Object { $usf.$_ -match '(?i)onedrive' } | ForEach-Object { "$_ -> $($usf.$_)" }
if ($kfm) {
    Add-Finding -Category 'Office365' -Type 'Check' -Name 'OneDrive Known Folder Move is active' -Detail ($kfm -join '; ') `
        -Flag 'Blocker' -Recommendation 'Review' `
        -Note 'Desktop/Documents/Pictures point into OneDrive. Move them back (OneDrive settings > Backup > Manage backup > Stop backup) BEFORE removing OneDrive. The Act script will skip OneDrive removal while this is active.'
}

# Policies that keep it from coming back
Add-Finding -Category 'Office365' -Type 'Registry' -Name 'Block OneDrive sync client (policy)' `
    -Detail 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive|DisableFileSyncNGSC|DWord|1' -Flag 'O365' -Recommendation 'Apply' -Note 'Prevents OneDrive from re-activating'
Add-Finding -Category 'Office365' -Type 'Registry' -Name 'Hide OneDrive in Explorer nav pane' `
    -Detail 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}|System.IsPinnedToNameSpaceTree|DWord|0' -Flag 'O365' -Recommendation 'Apply' -Note ''
Add-Finding -Category 'Office365' -Type 'Registry' -Name 'Block Teams machine-wide installer reinstall' `
    -Detail 'HKLM:\SOFTWARE\Microsoft\Office\Teams|PreventInstallationFromMsi|DWord|1' -Flag 'O365' -Recommendation 'Apply' -Note ''

# ---------------------------------------------------------------- 7. telemetry policy (Required level only)
Write-Host '[7/8] Telemetry settings...' -ForegroundColor Cyan
$tel = @(
    @{ N = 'Diagnostic data = Required only'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection|AllowTelemetry|DWord|1' }
    @{ N = 'No device name in diagnostic data'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection|AllowDeviceNameInTelemetry|DWord|0' }
    @{ N = 'Limit diagnostic log collection'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection|LimitDiagnosticLogCollection|DWord|1' }
    @{ N = 'Limit memory dump upload'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection|LimitDumpCollection|DWord|1' }
    @{ N = 'No feedback prompts'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection|DoNotShowFeedbackNotifications|DWord|1' }
    @{ N = 'Customer Experience Improvement Program off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows|CEIPEnable|DWord|0' }
    @{ N = 'Application telemetry (AIT) off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat|AITEnable|DWord|0' }
    @{ N = 'Inventory collector off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat|DisableInventory|DWord|1' }
    @{ N = 'Error reports: no extra data sent'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting|DontSendAdditionalData|DWord|1' }
    @{ N = 'Advertising ID off (policy)'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo|DisabledByGroupPolicy|DWord|1' }
    @{ N = 'Activity history off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|EnableActivityFeed|DWord|0' }
    @{ N = 'Activity history: do not publish'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|PublishUserActivities|DWord|0' }
    @{ N = 'Activity history: do not upload'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System|UploadUserActivities|DWord|0' }
    @{ N = 'Cortana off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search|AllowCortana|DWord|0' }
    @{ N = 'No web/Bing results in Start search'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search|DisableWebSearch|DWord|1' }
    @{ N = 'No web/Bing results in Start search (2)'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search|ConnectedSearchUseWeb|DWord|0' }
    @{ N = 'No search box suggestions'; D = 'HKCU:\Software\Policies\Microsoft\Windows\Explorer|DisableSearchBoxSuggestions|DWord|1' }
    @{ N = 'News and Interests (taskbar feed) off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds|EnableFeeds|DWord|0' }
    @{ N = 'Delivery Optimization: no peer-to-peer upload'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization|DODownloadMode|DWord|0' }
    @{ N = 'Handwriting data sharing off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC|PreventHandwritingDataSharing|DWord|1' }
    @{ N = 'Input personalization off'; D = 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization|AllowInputPersonalization|DWord|0' }
    @{ N = 'Tailored experiences off'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Privacy|TailoredExperiencesWithDiagnosticDataEnabled|DWord|0' }
    @{ N = 'Advertising ID off (user)'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo|Enabled|DWord|0' }
    @{ N = 'Feedback frequency = never'; D = 'HKCU:\Software\Microsoft\Siuf\Rules|NumberOfSIUFInPeriod|DWord|0' }
    @{ N = 'No silently installed suggested apps'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|SilentInstalledAppsEnabled|DWord|0' }
    @{ N = 'No Start menu suggestions'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|SystemPaneSuggestionsEnabled|DWord|0' }
    @{ N = 'No tips/tricks notifications'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|SoftLandingEnabled|DWord|0' }
    @{ N = 'No preinstalled promo apps'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|PreInstalledAppsEnabled|DWord|0' }
    @{ N = 'No OEM promo apps'; D = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager|OemPreInstalledAppsEnabled|DWord|0' }
)
foreach ($t in $tel) {
    $parts = $t.D -split '\|'
    $cur = try { (Get-ItemProperty -Path $parts[0] -Name $parts[1] -ErrorAction Stop).($parts[1]) } catch { '<not set>' }
    $rec = if ("$cur" -eq $parts[3]) { 'Keep' } else { 'Apply' }
    Add-Finding -Category 'Telemetry' -Type 'Registry' -Name $t.N -Detail $t.D -Company 'Windows' -State "current=$cur" `
        -Flag 'PhonesHome' -Recommendation $rec -Note $(if ($rec -eq 'Keep') { 'Already set' } else { '' })
}

# ---------------------------------------------------------------- 8. third-party updates (winget)
Write-Host '[8/8] Pending third-party updates (winget)...' -ForegroundColor Cyan
# Is a winget package installed per-user? Per-user installs (Slack, Zoom, ...) break or refuse when
# upgraded/removed from an elevated session, so they must be handled from a non-admin PowerShell.
function Get-WingetExe {
    $w = (Get-Command winget.exe -ErrorAction SilentlyContinue).Source
    if (-not $w) {
        $w = Get-ChildItem "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
             Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    return $w
}
function Test-WingetUserScope {
    param([string]$WingetExe, [string]$Id)
    if (-not $WingetExe -or -not $Id) { return $false }
    & $WingetExe list --id $Id --exact --scope user --accept-source-agreements --disable-interactivity *> $null
    return ($LASTEXITCODE -eq 0)
}

$DriverPattern = '(?i)driver|realtek|nvidia|amd software|radeon|intel.*(graphics|wireless|wi-fi|bluetooth|chipset|management engine|rapid storage|serial io)|ftdi|silabs|prolific|thunderbolt'
try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.WinGet.Client)) {
        if ($NoModuleInstall) { throw 'Microsoft.WinGet.Client not installed and -NoModuleInstall was given' }
        Write-Host '   Installing Microsoft.WinGet.Client module for the current user...'
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        Install-Module -Name Microsoft.WinGet.Client -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -ErrorAction Stop
    }
    Import-Module Microsoft.WinGet.Client -ErrorAction Stop
    $upd = @(Get-WinGetPackage -ErrorAction Stop | Where-Object { $_.IsUpdateAvailable })
    $wingetExe = Get-WingetExe
    if ($upd.Count) { Write-Host '   Checking which packages are per-user installs...' }
    foreach ($u in $upd) {
        $txt = "$($u.Name) $($u.Id)"
        if ($txt -match $O365Pattern)       { $rec = 'Skip';    $note = 'Being removed - do not upgrade' }
        elseif ($txt -match $StationPattern){ $rec = 'Review';  $note = 'Station software - upgrade between contests after reading release notes' }
        elseif ($txt -match $DriverPattern) { $rec = 'Review';  $note = 'Driver package - leave alone unless it fixes a stability problem' }
        else                                { $rec = 'Upgrade'; $note = '' }
        $avail = @($u.AvailableVersions)[0]
        $scope = 'machine'
        if ($rec -ne 'Skip' -and (Test-WingetUserScope $wingetExe $u.Id)) {
            $scope = 'user'
            $rec   = 'Review'
            $note  = (@($note, "Per-user install - upgrading from an admin session can break it. In a NON-admin PowerShell run: winget upgrade --id $($u.Id) -e") | Where-Object { $_ }) -join ' | '
        }
        Add-Finding -Category 'Updates' -Type 'Winget' -Name $u.Name -ItemName $u.Id -Detail "$($u.InstalledVersion) -> $avail" `
            -State "source=$($u.Source) scope=$scope" -Flag 'Update' -Recommendation $rec -Note $note
    }
    Write-Host "   $($upd.Count) package(s) have updates."
} catch {
    Write-Warning "WinGet module path failed: $($_.Exception.Message). Falling back to raw 'winget upgrade' output."
    $raw = try { & winget upgrade --include-unknown --accept-source-agreements 2>&1 | Out-String } catch { 'winget not found - install "App Installer" from the Microsoft Store.' }
    $raw | Set-Content (Join-Path $OutDir 'WingetRaw.txt') -Encoding UTF8
    Add-Finding -Category 'Updates' -Type 'Check' -Name 'winget list unavailable' -Detail 'See WingetRaw.txt' -Recommendation 'Review' -Note 'Could not build a structured update list'
}

# ---------------------------------------------------------------- 9. connections + DNS cache
$conRows = @(); $dnsRows = @()
if (-not $SkipConnections) {
    Write-Host "Sampling outbound connections ($ConnectionSamples samples, 10 s apart)..." -ForegroundColor Cyan
    $private = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fd|fc|127\.|::1$|0\.0\.0\.0|::$)'
    $seen = @{}
    for ($i = 1; $i -le $ConnectionSamples; $i++) {
        $procs = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_ }
        foreach ($c in Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue) {
            if ($c.RemoteAddress -match '^(127\.|::1$|0\.0\.0\.0)') { continue }
            $p = $procs[[int]$c.OwningProcess]
            $key = "$($p.ProcessName)|$($c.RemoteAddress)|$($c.RemotePort)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = [pscustomobject]@{
                Process = $p.ProcessName; PID = $c.OwningProcess; Path = $p.Path; Company = (Get-Company $p.Path)
                RemoteAddress = $c.RemoteAddress; RemotePort = $c.RemotePort
                Scope = $(if ($c.RemoteAddress -match $private) { 'LAN' } else { 'Internet' }); RemoteName = ''
            }
        }
        if ($i -lt $ConnectionSamples) { Start-Sleep -Seconds 10 }
    }
    $conRows = @($seen.Values | Sort-Object Scope, Process)
    $ips = @($conRows | Where-Object Scope -eq 'Internet' | Select-Object -ExpandProperty RemoteAddress -Unique | Select-Object -First 80)
    $ptr = @{}
    foreach ($ip in $ips) {
        try { $ptr[$ip] = (Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch {}
    }
    foreach ($r in $conRows) { if ($ptr[$r.RemoteAddress]) { $r.RemoteName = $ptr[$r.RemoteAddress] } }
    $conRows | Export-Csv (Join-Path $OutDir 'Connections.csv') -NoTypeInformation -Encoding UTF8

    $telDomains = '(?i)telemetry|vortex|watson|events\.data|self\.events|nexus\.officeapps|settings-win\.data|browser\.events|adobe\.io|analytics|metrics|crashlytics|sentry|segment\.io|mixpanel|appcenter|doubleclick|scorecardresearch'
    $dnsRows = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Entry -Unique | Sort-Object |
        ForEach-Object { [pscustomobject]@{ Host = $_; LooksLikeTelemetry = ($_ -match $telDomains) } })
    $dnsRows | Export-Csv (Join-Path $OutDir 'DnsCache.csv') -NoTypeInformation -Encoding UTF8
}

# ---------------------------------------------------------------- output
$findCsv = Join-Path $OutDir 'Findings.csv'
$Findings | Export-Csv $findCsv -NoTypeInformation -Encoding UTF8

$css = @'
<style>
body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:20px;color:#222}
h1{font-size:20px} h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc}
table{border-collapse:collapse;width:100%;margin-bottom:12px} th,td{border:1px solid #ddd;padding:4px 6px;vertical-align:top;text-align:left}
th{background:#f0f0f0} tr:nth-child(even){background:#fafafa} pre{background:#f6f6f6;padding:8px}
</style>
'@
$sections = New-Object System.Collections.Generic.List[string]
$sections.Add("<h1>Shack PC audit - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>")
$sections.Add("<h2>Hardware and OS</h2><pre>$([System.Net.WebUtility]::HtmlEncode(($hw -join "`n")))</pre>")
$sections.Add('<h2>Station health</h2>' + ($health | ConvertTo-Html -Fragment | Out-String))
foreach ($cat in 'Office365', 'Telemetry', 'Startup', 'ScheduledTask', 'Service', 'StationTuning', 'Updates') {
    $rows = @($Findings | Where-Object Category -eq $cat)
    if ($rows.Count -eq 0) { continue }
    $sections.Add("<h2>$cat ($($rows.Count))</h2>" + ($rows | Select-Object Id, Type, Name, State, Company, Flag, Recommendation, Action, Note, Detail | ConvertTo-Html -Fragment | Out-String))
}
if ($conRows) {
    $sections.Add("<h2>Outbound connections - Internet ($(@($conRows | Where-Object Scope -eq 'Internet').Count))</h2>" +
        ($conRows | Where-Object Scope -eq 'Internet' | Select-Object Process, Company, RemoteName, RemoteAddress, RemotePort, Path | ConvertTo-Html -Fragment | Out-String))
}
if ($dnsRows) {
    $sections.Add("<h2>Recently looked-up hosts that look like telemetry</h2>" +
        ($dnsRows | Where-Object LooksLikeTelemetry | Select-Object Host | ConvertTo-Html -Fragment | Out-String))
}
ConvertTo-Html -Head $css -Body ($sections -join "`n") -Title 'Shack PC audit' | Set-Content (Join-Path $OutDir 'Report.html') -Encoding UTF8

Write-Host ''
Write-Host '================ SUMMARY ================' -ForegroundColor Green
$Findings | Group-Object Category, Recommendation | Sort-Object Name | Format-Table @{ n = 'Category, Recommendation'; e = { $_.Name } }, Count -AutoSize | Out-String | Write-Host
Write-Host "Report folder : $OutDir"
Write-Host "Review        : $(Join-Path $OutDir 'Report.html')"
Write-Host "Edit Action   : $findCsv"
Write-Host ''
Write-Host 'Next: edit the Action column (blank = leave alone), then run:'
Write-Host "  .\ShackCleanup-Act.ps1 -FindingsCsv `"$findCsv`" -WhatIf     # dry run" -ForegroundColor Yellow
Write-Host "  .\ShackCleanup-Act.ps1 -FindingsCsv `"$findCsv`"             # for real" -ForegroundColor Yellow

Stop-Transcript | Out-Null
Start-Process (Join-Path $OutDir 'Report.html') -ErrorAction SilentlyContinue
