# Telemetry

## The goal: "Required" diagnostic data, nothing more

Windows has two diagnostic data levels: **Required** (formerly "Basic") and **Optional**
(formerly "Full"). On Windows 10/11 **Pro**, Required is the lowest level that's officially
supported. Setting `AllowTelemetry = 0` ("Security") is only honored on Enterprise, Education
and Server editions; on Pro it's treated as Required anyway.

These scripts set Required by policy and turn off everything layered on top of it.

## Why `DiagTrack` stays on

The **Connected User Experiences and Telemetry** service (`DiagTrack`) is what sends the
Required-level data. Disabling it doesn't give you a cleaner "Required" level. It turns diagnostics
off completely, which is outside Microsoft's supported configuration for Pro and can make Windows
Update troubleshooting harder.

The report lists it as **Review**. If you want it off anyway, set its Action to `Disable`.
`dmwappushservice` (WAP push message routing, used for MDM) defaults to **Disable**, since a
standalone station PC doesn't need it.

## Registry and policy settings

Each of these is a row in `Findings.csv`. It's **Apply** if the current value differs and **Keep**
if it's already set.

### Diagnostic data

| Setting | Path | Value |
|---|---|---|
| Diagnostic data = Required | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` | 1 |
| No device name in diagnostic data | `...\DataCollection\AllowDeviceNameInTelemetry` | 0 |
| Limit diagnostic log collection | `...\DataCollection\LimitDiagnosticLogCollection` | 1 |
| Limit memory-dump upload | `...\DataCollection\LimitDumpCollection` | 1 |
| No feedback prompts | `...\DataCollection\DoNotShowFeedbackNotifications` | 1 |
| Feedback frequency = never | `HKCU\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod` | 0 |

### Improvement programs and app telemetry

| Setting | Path | Value |
|---|---|---|
| Customer Experience Improvement Program off | `HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows\CEIPEnable` | 0 |
| Application Impact Telemetry off | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat\AITEnable` | 0 |
| Inventory Collector off | `...\AppCompat\DisableInventory` | 1 |
| Error reports: no extra data | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\DontSendAdditionalData` | 1 |

Windows Error Reporting itself stays on, so crash reports are still kept locally where you can
look at them in Reliability Monitor.

### Advertising, personalization, suggestions

| Setting | Path | Value |
|---|---|---|
| Advertising ID off (policy) | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo\DisabledByGroupPolicy` | 1 |
| Advertising ID off (user) | `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled` | 0 |
| Tailored experiences off | `HKCU\...\CurrentVersion\Privacy\TailoredExperiencesWithDiagnosticDataEnabled` | 0 |
| Input personalization off | `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization` | 0 |
| Handwriting data sharing off | `HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing` | 1 |
| No silently installed suggested apps | `HKCU\...\ContentDeliveryManager\SilentInstalledAppsEnabled` | 0 |
| No Start menu suggestions | `...\ContentDeliveryManager\SystemPaneSuggestionsEnabled` | 0 |
| No tips/tricks notifications | `...\ContentDeliveryManager\SoftLandingEnabled` | 0 |
| No preinstalled promo apps | `...\ContentDeliveryManager\PreInstalledAppsEnabled` | 0 |
| No OEM promo apps | `...\ContentDeliveryManager\OemPreInstalledAppsEnabled` | 0 |

### Activity history, search, feeds

| Setting | Path | Value |
|---|---|---|
| Activity history off | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableActivityFeed` | 0 |
| Don't publish activities | `...\System\PublishUserActivities` | 0 |
| Don't upload activities | `...\System\UploadUserActivities` | 0 |
| Cortana off | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana` | 0 |
| No web results in Start search | `...\Windows Search\DisableWebSearch` | 1 |
| No web results in Start search (2) | `...\Windows Search\ConnectedSearchUseWeb` | 0 |
| No search box suggestions | `HKCU\Software\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions` | 1 |
| News and Interests (taskbar feed) off | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds\EnableFeeds` | 0 |

### Delivery Optimization

| Setting | Path | Value |
|---|---|---|
| No peer-to-peer upload | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode` | 0 (HTTP only) |

Updates still download normally from Microsoft. This just stops the PC from **uploading** update
pieces to other PCs, which you don't want using bandwidth on a remote-controlled station.

## Scheduled tasks (Disable)

| Task | What it does |
|---|---|
| `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser` | Scans installed apps and sends compatibility data (also used for upgrade-eligibility checks) |
| `...\Application Experience\ProgramDataUpdater` | Program telemetry |
| `...\Application Experience\PcaPatchDbTask` | Compatibility-database telemetry |
| `\Microsoft\Windows\Customer Experience Improvement Program\Consolidator` | Improvement-program upload |
| `...\Customer Experience Improvement Program\UsbCeip` | USB usage telemetry |
| `...\Customer Experience Improvement Program\KernelCeipTask` | Kernel improvement-program data |
| `\Microsoft\Windows\Autochk\Proxy` | Collects and uploads autochk improvement-program data |
| `\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector` | Uploads disk diagnostics |
| `\Microsoft\Windows\Feedback\Siuf\DmClient` / `DmClientOnScenarioDownload` | Feedback Hub data |
| `\Microsoft\Windows\Maps\MapsUpdateTask` / `MapsToastTask` | Offline-maps update checks |

Tasks that don't exist on your build are logged as `OK (not present)`.

## What's deliberately left alone

- Windows Update, Defender, SmartScreen, and certificate and root-store updates: these are security.
- Windows Error Reporting (local)
- Edge's own updater: browser security
- Time sync. Your station's NTP setup is yours.

## Verifying

After a reboot:

- *Settings > Privacy > Diagnostics & feedback* should say "Some settings are managed by your organization", with Required selected.
- Re-run the report. All Telemetry rows should show `Keep` / `Already set`.
- Look at the "telemetry-looking hosts" table in `Report.html`. It won't be empty, since Required-level data still goes out, but Office, `nexus.officeapps`, Bing feed and advertising hosts should be gone.
