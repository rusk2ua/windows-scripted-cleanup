# The report (`ShackCleanup-Report.ps1`)

The report only reads the system. It writes everything it finds to a timestamped folder and leaves
the decisions to you.

## Output files

All files are written to `<OutRoot>\Report-<yyyyMMdd-HHmmss>\`. The default `OutRoot` is
`C:\ShackCleanup`.

| File | Contents |
|---|---|
| `Findings.csv` | One row per actionable item. **This is what you edit and feed to the Act script.** See [findings-csv.md](findings-csv.md). |
| `Report.html` | Everything in readable form: hardware, station health, each findings category, internet connections, telemetry-looking DNS lookups. Opens automatically. |
| `Hardware.txt` | Hardware and OS summary |
| `Connections.csv` | Established TCP connections by process, with reverse-DNS names and a LAN/Internet scope |
| `DnsCache.csv` | Every hostname in the DNS client cache, with a `LooksLikeTelemetry` flag |
| `WingetRaw.txt` | Only written if the WinGet module couldn't be used; raw `winget upgrade` output |
| `Transcript.txt` | Console transcript |

## What it collects

### 1. Hardware and OS (`Hardware.txt`)

- Computer model and baseboard (this identifies the exact NUC or other model)
- BIOS version and date
- CPU: model, cores, threads, socket designation. A soldered (BGA) CPU, which every Intel NUC has, can't be upgraded.
- RAM total, each module (slot, size, speed, part number), slot count, and the maximum the board reports. NUC firmware often under-reports the maximum, so check the model's spec sheet.
- Each disk: size, media type, bus, health, and where available wear %, temperature and power-on hours
- OS edition, version, build and revision, install date, last boot and uptime
- Secure Boot and TPM status (relevant for Windows 11 eligibility)
- The most recent installed update. If it's more than 45 days old, there's a warning to check Windows 10 ESU enrollment.

### 2. Station health

| Check | Why it matters |
|---|---|
| Active power plan | Baseline |
| USB selective suspend (AC) | When enabled, Windows can power down idle USB ports. That's a frequent cause of CAT port, USB audio codec, and USB-serial dropouts. If it's on, a `StationTuning` finding is added. |
| Fast Startup | Hybrid shutdown doesn't fully re-initialize drivers. If it's on, a `StationTuning` finding is added. |
| Windows time service | `w32tm /query /status`. FT8/FT4/Q65 need under about 1 s of error. |
| COM ports present | Snapshot of serial ports (USB-serial, virtual ports) and their status, to compare after changes |
| Reboot pending | Whether Windows Update is waiting on a reboot |
| Top System errors (14 days) | Most frequent critical and error events. Look for Kernel-Power 41, WHEA, disk, and USB errors. |

### 3. Startup items

- Registry Run keys: `HKLM\...\Run`, `HKLM\WOW6432Node\...\Run`, `HKCU\...\Run`
- Startup folders: the per-user one and the all-users one
- The current enabled/disabled state, read from the same `StartupApproved` keys Task Manager uses
- Stock Windows entries (company "Microsoft", not matched by a rule) are skipped to cut the noise

### 4. Scheduled tasks

- Every task outside `\Microsoft\` is listed and classified.
- Everything under `\Microsoft\Office\` is listed as Office365.
- A fixed list of Windows telemetry tasks (Compatibility Appraiser, the improvement-program tasks, Autochk Proxy, Disk Diagnostic data collector, the Feedback tasks, Maps) is listed under Telemetry with **Disable**.
- Other `\Microsoft\Windows\` tasks are not listed.

### 5. Services

- Non-Microsoft services that aren't already disabled are classified.
- Microsoft services are listed only if a specific rule matches them (Office/OneDrive/Teams, the Edge updater). Generic words like "update" are ignored for Microsoft services, so Windows Update itself never shows up as a candidate.
- `DiagTrack` is listed as **Review** with a note. See [telemetry.md](telemetry.md).
- `dmwappushservice` is listed as **Disable**.
- The start mode is recorded precisely: Automatic, AutomaticDelayed, Manual or Disabled. That lets undo restore it exactly.

### 6. Office 365 / OneDrive / Teams

- Uninstall registry entries (64-bit, 32-bit and per-user) whose name matches Office/365/OneDrive/Teams/Skype/Outlook/OneNote. Visual C++ runtimes, .NET, Edge and the like are excluded. Each entry is typed by its uninstall method: `C2R`, `MSI`, `OneDrive`, `TeamsClassic` or `Exe`.
- Store apps (installed for any user, or provisioned for new users): the Office hub app, OneNote, Store Office, new Outlook, new and consumer Teams, Skype, and Mail & Calendar. These default to Remove. To Do, People, Bing News and Bing Weather default to Review.
- A **Known Folder Move** check: whether Desktop, Documents, Pictures or Downloads are redirected into OneDrive. If so, a `Blocker` row is added.
- Three policy rows that keep OneDrive and Teams from coming back

### 7. Telemetry settings

About 30 registry and policy values, each with its current value. A row defaults to **Apply** if
the value differs from the target, and **Keep** if it's already set. The full list is in
[telemetry.md](telemetry.md).

### 8. Third-party updates

- This step uses the `Microsoft.WinGet.Client` module (`Get-WinGetPackage`). Unlike the `winget upgrade` text output, it doesn't truncate long names or IDs.
- If the module is missing, it's installed for the **current user only**. That may also install the NuGet package provider.
- Each package with an update gets a row:
  - **Skip** for Office/Teams/OneDrive, since they're being removed
  - **Review** for station software and driver packages
  - **Upgrade** for everything else
- Each package is also checked with `winget list --id <id> --exact --scope user`. **Per-user installs** (Slack, Zoom, and other apps that live in `%LOCALAPPDATA%`) are tagged `scope=user` and downgraded to **Review**, with a note giving the non-admin command. Upgrading or removing per-user apps from an elevated session can fail or leave them broken.

### 9. Outbound connections and DNS cache

- Three snapshots (configurable), 10 seconds apart, of established TCP connections. Each one is mapped to its process, the executable path and the publisher.
- Internet addresses (not LAN) get a reverse-DNS lookup, capped at 80 unique IPs, with a quick timeout.
- The DNS client cache is dumped with telemetry-looking hostnames flagged: `vortex`, `watson`, `events.data`, `nexus.officeapps`, analytics and crash-reporting domains, and similar.

This is a snapshot, not a firewall log. Something that phones home once a day won't necessarily
show up. For long-term monitoring, use a tool like TCPView, GlassWire, or your router's logs.
