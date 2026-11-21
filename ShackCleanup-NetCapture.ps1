#Requires -Version 5.1
<#
.SYNOPSIS
    Captures outbound network traffic for a set time and reports who talks to whom: every
    connection, the program or Windows service that made it, and what the destination is
    (Windows Update, Required-level telemetry, ads/Bing, Office/OneDrive, third party...).

.DESCRIPTION
    Read-only as far as your settings go. For the capture it temporarily turns on:
      - Windows Filtering Platform connection auditing (Security log event 5156), which
        records every allowed connection with its process, and
      - the DNS Client operational log, which records every name looked up.
    Both are put back exactly as they were when the capture ends, including after Ctrl+C.
    Use -NoConnectionAudit to skip the auditing and sample open TCP connections instead
    (lighter, but brief connections can be missed).

    Output: <OutRoot>\NetCapture-<timestamp>\
        Report.html      <- start here: verdicts, then details
        Summary.csv      <- one row per process + destination
        Connections.csv  <- every outbound connection seen
        DnsQueries.csv   <- every name looked up
        Transcript.txt

.EXAMPLE
    .\ShackCleanup-NetCapture.ps1                  # 4 hours
    .\ShackCleanup-NetCapture.ps1 -Minutes 60
#>
[CmdletBinding()]
param(
    [int]$Minutes = 240,
    [string]$OutRoot = 'C:\ShackCleanup',
    [switch]$NoConnectionAudit,
    [int]$PollSeconds = 60
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------- host classification (tested)
$PrivatePattern = '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|22[4-9]\.|23\d\.|255\.255\.255\.255|0\.0\.0\.0|::1$|fe80:|f[cd][0-9a-f]{2}:|ff[0-9a-f]{2}:|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)'
$HostRules = @(
    @{ P = 'copilot|sydney\.bing\.com';                                                        C = 'Copilot';                                   V = 'Should be gone'; N = 'Copilot was removed and turned off by policy' }
    @{ P = '(^|\.)(us-|eu-)?v(10|20)c?\.(events|vortex-win)\.data\.microsoft\.com$';          C = 'Telemetry (Required level)';                V = 'Expected';       N = 'Required diagnostic data - sent while DiagTrack runs, which you chose to keep' }
    @{ P = '(^|\.)settings-win\.data\.microsoft\.com$';                                         C = 'Windows configuration service';             V = 'Expected';       N = 'Windows fetches its feature/config settings here' }
    @{ P = 'watson|wer\.microsoft\.com';                                                        C = 'Error reporting';                           V = 'Expected';       N = 'Only after a crash; extra data is blocked by policy' }
    @{ P = '(^|\.)activity\.windows\.com$';                                                     C = 'Activity history';                          V = 'Should be gone'; N = 'Activity history upload is turned off by policy' }
    @{ P = 'events\.data\.microsoft\.com$|vortex|telecommand|telemetry|\.aria\.microsoft\.com$|dmd\.metaservices|browser\.events\.data\.msn'; C = 'Telemetry (other)'; V = 'Review'; N = 'Check the process: Edge sends some at its Required level; anything else is worth a look' }
    @{ P = '(^|\.)(msn\.com|bing\.com|bing\.net|msftstatic\.com|iris\.microsoft\.com)$|tile-service\.weather|(^|\.)weather\.microsoft\.com$'; C = 'News, Bing, Widgets, ads'; V = 'Should be gone'; N = 'Widgets, News, Bing search and Start ads were removed - unless the process is msedge (Edge start page)' }
    @{ P = '(^|\.)(office\.com|office\.net|officeapps\.live\.com|onedrive\.com|onedrive\.live\.com|sharepoint\.com|skype\.com|teams\.microsoft\.com|teams\.live\.com|outlook\.com|outlook\.office365\.com)$'; C = 'Office / OneDrive / Teams'; V = 'Should be gone'; N = 'Office 365, OneDrive and Teams were removed' }
    @{ P = '(^|\.)(login\.live\.com|account\.live\.com|login\.microsoftonline\.com|msauth\.net|msftauth\.net|live\.com|live\.net)$'; C = 'Microsoft account sign-in'; V = 'Review'; N = 'You use a local account; the Store and Edge may still check in here' }
    @{ P = '(^|\.)(windowsupdate\.com|update\.microsoft\.com|delivery\.mp\.microsoft\.com|wdcp\.microsoft\.com|wdcpalt\.microsoft\.com|wd\.microsoft\.com|smartscreen\.microsoft\.com|smartscreen-prod\.microsoft\.com|checkappexec\.microsoft\.com|urs\.microsoft\.com|definitionupdates\.microsoft\.com|displaycatalog\.mp\.microsoft\.com|storeedgefd\.dsx\.mp\.microsoft\.com|storecatalogrevocation\.storequality\.microsoft\.com|tsfe\.trafficshaping\.dsp\.mp\.microsoft\.com)$'; C = 'Windows Update, Defender, Store'; V = 'Expected'; N = 'Security and update traffic - keep it' }
    @{ P = '(^|\.)(msftconnecttest\.com|msftncsi\.com)$';                                       C = 'Network connectivity check';                V = 'Expected';       N = 'How Windows decides whether you are online' }
    @{ P = '(^|\.)(time\.windows\.com|nist\.gov|pool\.ntp\.org)$|^(time|ntp)\d*\.';               C = 'Time sync';                                 V = 'Expected';       N = 'Dimension 4 / time servers' }
    @{ P = 'crl\.|ocsp|(^|\.)(digicert\.com|lencr\.org|globalsign\.com|sectigo\.com|usertrust\.com|ctldl\.windowsupdate\.com|msocsp\.com)$|pki\.'; C = 'Certificate checks'; V = 'Expected'; N = 'Certificate revocation checks - keep them' }
    @{ P = '(^|\.)(edge\.microsoft\.com|msedge\.net|edgedl\.me\.gvt1\.com)$|config\.edge\.skype\.com'; C = 'Edge (updates, config)'; V = 'Expected'; N = 'Edge updates and settings' }
    @{ P = '(^|\.)(winget\.microsoft\.com|github\.com|githubusercontent\.com|powershellgallery\.com|nuget\.org)$|winget\.azureedge\.net'; C = 'winget / GitHub / PowerShell Gallery'; V = 'Expected'; N = 'Package and repo traffic you started' }
    @{ P = '(^|\.)(microsoft\.com|windows\.com|windows\.net|microsoft\.net|azure\.com|azureedge\.net|azurefd\.net|trafficmanager\.net|akamaized\.net|akamaiedge\.net|akadns\.net|msedge\.net)$'; C = 'Microsoft (other)'; V = 'Review'; N = 'Microsoft or a Microsoft CDN - check which process' }
)
function Get-HostCategory {
    param([string]$HostName, [string]$Ip, [string]$Process)
    if ($Ip -and $Ip -match $PrivatePattern) { return [pscustomobject]@{ Category = 'LAN / local'; Verdict = 'LAN'; Note = 'Stays on your network' } }
    $h = "$HostName".Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $h) { return [pscustomobject]@{ Category = 'No DNS name'; Verdict = 'Review'; Note = 'Connected by IP address; see the reverse-DNS name' } }
    foreach ($r in $HostRules) {
        if ($h -match $r.P) {
            # Edge's own start / new-tab page pulls from MSN: worth a look, but it isn't Windows' Widgets or Start ads coming back
            if ($r.C -eq 'News, Bing, Widgets, ads' -and $Process -match '^msedge') {
                return [pscustomobject]@{ Category = $r.C; Verdict = 'Review'; Note = 'Edge start/new-tab page - set Edge to open a blank page to stop it' }
            }
            return [pscustomobject]@{ Category = $r.C; Verdict = $r.V; Note = $r.N }
        }
    }
    return [pscustomobject]@{ Category = 'Third party'; Verdict = 'Review'; Note = 'Not Microsoft - check that the process is something you installed' }
}
# Programs that should not be running at all after the cleanup
$ShouldBeGoneProcesses = 'OneDrive', 'Teams', 'ms-teams', 'Widgets', 'WidgetService', 'PhoneExperienceHost', 'YourPhone', 'CrossDeviceService',
                         'CompatTelRunner', 'DeviceCensus', 'GameBar', 'GameBarFTServer', 'XboxPcApp', 'Copilot', 'M365Copilot', 'Clipchamp', 'olk', 'HxOutlook'
# ---------------------------------------------------------------- end host classification

# ---------------------------------------------------------------- prerequisites
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Run this from an elevated PowerShell window (Run as administrator).'; exit 1
}
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = Join-Path $OutRoot "NetCapture-$stamp"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Start-Transcript -Path (Join-Path $OutDir 'Transcript.txt') | Out-Null

$AuditGuid = '{0CCE9226-69AE-11D9-BED3-505054503030}'   # Filtering Platform Connection
$DnsLogName = 'Microsoft-Windows-DNS-Client/Operational'
$useAudit = -not $NoConnectionAudit
$state = @{ AuditBefore = $null; DnsWasEnabled = $null; DnsOldSize = $null; SecOldSize = $null }

$conns   = New-Object System.Collections.Generic.List[object]
$dnsRows = New-Object System.Collections.Generic.List[object]
$ipName  = @{}
$pidInfo = @{}
$seenProcs = @{}
$companyCache = @{}

function Get-CompanyName {
    param([string]$Path)
    if (-not $Path) { return '' }
    if ($companyCache.ContainsKey($Path)) { return $companyCache[$Path] }
    $c = ''
    try { if (Test-Path -LiteralPath $Path) { $c = (Get-Item -LiteralPath $Path).VersionInfo.CompanyName } } catch {}
    $companyCache[$Path] = $c
    return $c
}

function Update-PidMap {
    $svcByPid = @{}
    foreach ($s in @(Get-CimInstance Win32_Service -Filter 'ProcessId > 0' -ErrorAction SilentlyContinue)) {
        $k = [int]$s.ProcessId
        if (-not $svcByPid.ContainsKey($k)) { $svcByPid[$k] = New-Object System.Collections.Generic.List[string] }
        $svcByPid[$k].Add($s.Name)
    }
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $path = $null; try { $path = $p.Path } catch {}
        $svc = if ($svcByPid.ContainsKey($p.Id)) { ($svcByPid[$p.Id] | Sort-Object) -join ',' } else { '' }
        $pidInfo[[int]$p.Id] = [pscustomobject]@{ Name = $p.ProcessName; Path = $path; Services = $svc }
        if (-not $seenProcs.ContainsKey($p.ProcessName)) { $seenProcs[$p.ProcessName] = Get-Date }
    }
}

function Resolve-Pid {
    param([int]$ProcessId, [string]$AppPath)
    if ($pidInfo.ContainsKey($ProcessId)) { return $pidInfo[$ProcessId] }
    $name = if ($AppPath) { [IO.Path]::GetFileNameWithoutExtension($AppPath) } else { "pid $ProcessId" }
    return [pscustomobject]@{ Name = $name; Path = $AppPath; Services = '' }
}

function Convert-DevicePath {
    param([string]$Path)
    # \device\harddiskvolume3\windows\system32\svchost.exe -> C:\windows\system32\svchost.exe
    if ($Path -match '^\\device\\harddiskvolume\d+\\(.*)$') { return "$env:SystemDrive\$($Matches[1])" }
    return $Path
}

$script:LastSecId = 0; $script:LastDnsId = 0
function Get-NewRecordId { param($LogName) try { (Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop).RecordId } catch { 0 } }

function Read-Audit {
    $xp = "*[System[(EventID=5156) and (EventRecordID > $($script:LastSecId))]]"
    $events = @(); try { $events = @(Get-WinEvent -LogName Security -FilterXPath $xp -ErrorAction Stop) } catch {}
    foreach ($e in $events) {
        if ($e.RecordId -gt $script:LastSecId) { $script:LastSecId = $e.RecordId }
        $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        if ($d['Direction'] -ne '%%14593') { continue }                       # outbound only
        $dst = "$($d['DestAddress'])"
        if ($dst -match '^(127\.|::1$|0\.0\.0\.0)') { continue }
        $app = Convert-DevicePath $d['Application']
        $pi = Resolve-Pid ([int]$d['ProcessID']) $app
        $conns.Add([pscustomobject]@{
            Time = $e.TimeCreated; PID = [int]$d['ProcessID']; Process = $pi.Name; Services = $pi.Services; Path = $(if ($pi.Path) { $pi.Path } else { $app })
            DestIP = $dst; DestPort = $d['DestPort']; Protocol = $(switch ($d['Protocol']) { '6' { 'TCP' } '17' { 'UDP' } default { $d['Protocol'] } }); Source = 'audit'
        })
    }
}

$script:SampleSeen = @{}
function Read-TcpSample {
    foreach ($c in @(Get-NetTCPConnection -State Established, SynSent -ErrorAction SilentlyContinue)) {
        if ("$($c.RemoteAddress)" -match '^(127\.|::1$|0\.0\.0\.0)') { continue }
        $key = "$($c.OwningProcess)|$($c.RemoteAddress)|$($c.RemotePort)|$($c.LocalPort)"
        if ($script:SampleSeen.ContainsKey($key)) { continue }
        $script:SampleSeen[$key] = $true
        $pi = Resolve-Pid ([int]$c.OwningProcess) $null
        $conns.Add([pscustomobject]@{
            Time = Get-Date; PID = [int]$c.OwningProcess; Process = $pi.Name; Services = $pi.Services; Path = $pi.Path
            DestIP = "$($c.RemoteAddress)"; DestPort = "$($c.RemotePort)"; Protocol = 'TCP'; Source = 'sample'
        })
    }
}

function Read-Dns {
    $xp = "*[System[(EventID=3008) and (EventRecordID > $($script:LastDnsId))]]"
    $events = @(); try { $events = @(Get-WinEvent -LogName $DnsLogName -FilterXPath $xp -ErrorAction Stop) } catch {}
    foreach ($e in $events) {
        if ($e.RecordId -gt $script:LastDnsId) { $script:LastDnsId = $e.RecordId }
        $d = @{}; foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        $q = "$($d['QueryName'])".TrimEnd('.')
        if (-not $q) { continue }
        $res = "$($d['QueryResults'])"
        foreach ($m in [regex]::Matches($res, '(?<![\w:])((\d{1,3}\.){3}\d{1,3})|([0-9a-f]{1,4}(:[0-9a-f]{0,4}){2,7})')) {
            $ip = $m.Value -replace '^::ffff:', ''
            if (-not $ipName.ContainsKey($ip)) { $ipName[$ip] = $q }
        }
        $pi = Resolve-Pid ([int]$e.ProcessId) $null
        $dnsRows.Add([pscustomobject]@{ Time = $e.TimeCreated; Name = $q; Status = $d['QueryStatus']; RequestedByPid = $e.ProcessId; Process = $pi.Name; Services = $pi.Services })
    }
}

# ---------------------------------------------------------------- run
$finished = $false
$start = Get-Date
try {
    Write-Host "Network capture: $Minutes minutes, output in $OutDir" -ForegroundColor Cyan

    # DNS Client log on (and big enough)
    $dl = Get-WinEvent -ListLog $DnsLogName -ErrorAction Stop
    $state.DnsWasEnabled = $dl.IsEnabled; $state.DnsOldSize = $dl.MaximumSizeInBytes
    if (-not $dl.IsEnabled -or $dl.MaximumSizeInBytes -lt 20MB) {
        $dl.IsEnabled = $true; if ($dl.MaximumSizeInBytes -lt 20MB) { $dl.MaximumSizeInBytes = 20MB }; $dl.SaveChanges()
    }
    $script:LastDnsId = Get-NewRecordId $DnsLogName

    if ($useAudit) {
        $state.AuditBefore = (auditpol /get /subcategory:"$AuditGuid" /r | Where-Object { $_ } | ConvertFrom-Csv | Select-Object -First 1).'Inclusion Setting'
        if (-not $state.AuditBefore) { $state.AuditBefore = 'No Auditing (assumed - could not read the old setting)' }
        $sl = Get-WinEvent -ListLog Security
        $state.SecOldSize = $sl.MaximumSizeInBytes
        if ($sl.MaximumSizeInBytes -lt 128MB) { try { $sl.MaximumSizeInBytes = 128MB; $sl.SaveChanges() } catch { Write-Warning "Could not enlarge the Security log: $($_.Exception.Message)" } }
        $script:LastSecId = Get-NewRecordId 'Security'
        & auditpol /set /subcategory:"$AuditGuid" /success:enable | Out-Null
        Write-Host "   Connection auditing on (was: $($state.AuditBefore)); it will be put back at the end."
    } else {
        Write-Host '   Connection auditing skipped; sampling open TCP connections instead.'
    }

    Update-PidMap
    $start = Get-Date; $deadline = $start.AddMinutes($Minutes); $nextNote = $start.AddMinutes(15)
    while ((Get-Date) -lt $deadline) {
        Update-PidMap
        Read-Dns
        if ($useAudit) { Read-Audit } else { Read-TcpSample }
        $left = [int]($deadline - (Get-Date)).TotalMinutes
        Write-Progress -Activity 'Network capture' -Status "$left min left - $($conns.Count) connections, $($dnsRows.Count) lookups" -PercentComplete ([math]::Min(100, 100 * ((Get-Date) - $start).TotalMinutes / $Minutes))
        if ((Get-Date) -ge $nextNote) { Write-Host ("   {0:HH:mm}  {1} connections, {2} lookups so far" -f (Get-Date), $conns.Count, $dnsRows.Count); $nextNote = $nextNote.AddMinutes(15) }
        Start-Sleep -Seconds $PollSeconds
    }
    Read-Dns; if ($useAudit) { Read-Audit } else { Read-TcpSample }
    $finished = $true
}
finally {
    # ---------------------------------------------------------------- put everything back
    Write-Progress -Activity 'Network capture' -Completed
    if ($useAudit -and $null -ne $state.AuditBefore) {
        $s = if ($state.AuditBefore -match 'Success') { 'enable' } else { 'disable' }
        $f = if ($state.AuditBefore -match 'Failure') { 'enable' } else { 'disable' }
        & auditpol /set /subcategory:"$AuditGuid" /success:$s /failure:$f | Out-Null
        Write-Host "   Connection auditing restored to: $($state.AuditBefore)"
    }
    try {
        if ($null -ne $state.SecOldSize) { $sl = Get-WinEvent -ListLog Security; if ($sl.MaximumSizeInBytes -ne $state.SecOldSize) { $sl.MaximumSizeInBytes = $state.SecOldSize; $sl.SaveChanges() } }
        if ($null -ne $state.DnsWasEnabled) {
            $dl = Get-WinEvent -ListLog $DnsLogName
            $dl.IsEnabled = $state.DnsWasEnabled; $dl.MaximumSizeInBytes = $state.DnsOldSize; $dl.SaveChanges()
            Write-Host "   DNS Client log restored (enabled: $($state.DnsWasEnabled))"
        }
    } catch { Write-Warning "Could not restore a log setting: $($_.Exception.Message)" }
    if (-not $finished) { Write-Warning 'Capture stopped early - reporting what was collected.' }

    # ---------------------------------------------------------------- analyse
    Write-Host 'Analysing...' -ForegroundColor Cyan
    $unknownIps = @($conns | Where-Object { -not $ipName.ContainsKey($_.DestIP) -and $_.DestIP -notmatch $PrivatePattern } | Select-Object -ExpandProperty DestIP -Unique | Select-Object -First 150)
    $ptr = @{}
    foreach ($ip in $unknownIps) { try { $ptr[$ip] = (Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Select-Object -First 1).NameHost } catch {} }

    $rows = foreach ($c in $conns) {
        $hn = if ($ipName.ContainsKey($c.DestIP)) { $ipName[$c.DestIP] } else { '' }
        $cat = Get-HostCategory -HostName $hn -Ip $c.DestIP -Process $c.Process
        $who = if ($c.Services) { "$($c.Process) ($($c.Services))" } else { $c.Process }
        $co = Get-CompanyName $c.Path
        [pscustomobject]@{
            Time = $c.Time; Who = $who; Process = $c.Process; Services = $c.Services; Publisher = $co; Path = $c.Path
            Host = $hn; ReverseDns = $(if ($ptr.ContainsKey($c.DestIP)) { $ptr[$c.DestIP] } else { '' }); DestIP = $c.DestIP; DestPort = $c.DestPort; Protocol = $c.Protocol
            Category = $cat.Category; Verdict = $cat.Verdict; Note = $cat.Note
        }
    }
    $rows = @($rows)
    $rows | Export-Csv (Join-Path $OutDir 'Connections.csv') -NoTypeInformation -Encoding UTF8
    $dnsRows | Export-Csv (Join-Path $OutDir 'DnsQueries.csv') -NoTypeInformation -Encoding UTF8

    $summary = @($rows | Group-Object Who, Host, DestIP, Category, Verdict | ForEach-Object {
        $f = $_.Group[0]
        $times = @($_.Group | ForEach-Object Time | Sort-Object)
        [pscustomobject]@{
            Verdict = $f.Verdict; Category = $f.Category; Who = $f.Who; Publisher = $f.Publisher
            Destination = $(if ($f.Host) { $f.Host } elseif ($f.ReverseDns) { "$($f.DestIP) ($($f.ReverseDns))" } else { $f.DestIP })
            Ports = (($_.Group | ForEach-Object { "$($_.Protocol)/$($_.DestPort)" } | Sort-Object -Unique) -join ' ')
            Count = $_.Count; First = $times[0]; Last = $times[-1]; Note = $f.Note
        }
    })
    $order = @{ 'Should be gone' = 0; 'Review' = 1; 'Expected' = 2; 'LAN' = 3 }
    $summary = @($summary | Sort-Object @{ e = { $order[$_.Verdict] } }, Category, Who, Destination)
    $summary | Export-Csv (Join-Path $OutDir 'Summary.csv') -NoTypeInformation -Encoding UTF8

    $badProcs = @($seenProcs.Keys | Where-Object { $ShouldBeGoneProcesses -contains $_ } | Sort-Object | ForEach-Object { [pscustomobject]@{ Process = $_; FirstSeen = $seenProcs[$_] } })

    # ---------------------------------------------------------------- report
    $css = '<style>body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;margin:20px;color:#222}h1{font-size:20px}h2{font-size:16px;margin-top:26px;border-bottom:1px solid #ccc}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}th{background:#f0f0f0}tr:nth-child(even){background:#fafafa}</style>'
    $sec = New-Object System.Collections.Generic.List[string]
    $mins = [int]((Get-Date) - $start).TotalMinutes
    $sec.Add("<h1>Network capture - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>")
    $sec.Add("<p>Captured $mins minutes; $($rows.Count) outbound connections, $($dnsRows.Count) DNS lookups. Method: $(if ($useAudit) { 'connection auditing (every connection)' } else { 'TCP sampling every ' + $PollSeconds + ' s' }).</p>")
    $sec.Add('<h2>Verdicts</h2>' + ($summary | Group-Object Verdict | Select-Object @{ n = 'Verdict'; e = { $_.Name } }, @{ n = 'Destinations'; e = { $_.Count } }, @{ n = 'Connections'; e = { ($_.Group | Measure-Object Count -Sum).Sum } } | ConvertTo-Html -Fragment | Out-String))
    if ($badProcs) { $sec.Add('<h2>Programs that should not be running</h2>' + ($badProcs | ConvertTo-Html -Fragment | Out-String)) }
    foreach ($v in 'Should be gone', 'Review', 'Expected', 'LAN') {
        $part = @($summary | Where-Object Verdict -eq $v)
        if ($part.Count) { $sec.Add("<h2>$v ($($part.Count))</h2>" + ($part | Select-Object Category, Who, Publisher, Destination, Ports, Count, First, Last, Note | ConvertTo-Html -Fragment | Out-String)) }
    }
    ConvertTo-Html -Head $css -Body ($sec -join "`n") -Title 'Network capture' | Set-Content (Join-Path $OutDir 'Report.html') -Encoding UTF8

    Write-Host ''
    Write-Host '================ RESULT ================' -ForegroundColor Green
    $summary | Group-Object Verdict | Sort-Object @{ e = { $order[$_.Name] } } | Format-Table @{ n = 'Verdict'; e = { $_.Name } }, @{ n = 'Destinations'; e = { $_.Count } } -AutoSize | Out-String -Width 200 | Write-Host
    $gone = @($summary | Where-Object Verdict -eq 'Should be gone')
    if ($gone) { Write-Host 'Should be gone:' -ForegroundColor Yellow; $gone | Format-Table Who, Destination, Count -AutoSize | Out-String -Width 200 | Write-Host }
    if ($badProcs) { Write-Host "Programs that should not be running: $(($badProcs.Process) -join ', ')" -ForegroundColor Yellow }
    Write-Host "Report: $(Join-Path $OutDir 'Report.html')"
    Stop-Transcript | Out-Null
    Start-Process (Join-Path $OutDir 'Report.html') -ErrorAction SilentlyContinue
}
