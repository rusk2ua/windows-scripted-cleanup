# windows-scripted-cleanup

PowerShell scripts for auditing and slimming down a **Windows 10/11 ham radio station PC**:
remove Microsoft 365 / Office / OneDrive / Teams, cut Windows telemetry back to the
*Required* level, flag (and optionally disable) anything that phones home or runs a background
updater, update third-party apps through `winget`, and fix two power settings that are known to
cause USB/CAT/audio dropouts. The radio software and drivers are left alone.

It works in three steps: **report, review, act**. Nothing changes until you've reviewed a CSV and
said yes, and every reversible change can be rolled back.

> Built for a shack PC that controls multiple radios, where stability matters more than features.
> The defaults are conservative: radio software, USB-serial drivers, audio drivers, and time-sync
> tools are never recommended for removal.

---

## What's in the box

| Script | What it does | Changes the system? |
|---|---|---|
| [`ShackCleanup-Report.ps1`](ShackCleanup-Report.ps1) | Inventories hardware, station health, Office 365 remnants, startup items, scheduled tasks, services, telemetry settings, outbound connections, and pending `winget` updates. Writes `Findings.csv` + `Report.html`. | **No.** The only exception: it installs Microsoft's `Microsoft.WinGet.Client` PowerShell module for the current user if it's missing (`-NoModuleInstall` skips that). |
| [`ShackCleanup-Act.ps1`](ShackCleanup-Act.ps1) | Applies the actions you approved in `Findings.csv`. Creates a restore point first, exports the affected registry keys, and logs every change to `ChangeLog.csv`. Supports `-WhatIf`. | Yes |
| [`ShackCleanup-Undo.ps1`](ShackCleanup-Undo.ps1) | Reads `ChangeLog.csv` and reverses registry, startup, scheduled-task, service, and power changes. | Yes (puts things back) |

## Quick start

```powershell
# 1. Elevated PowerShell (Run as administrator), logged in as your normal station user
cd C:\ShackCleanup
Get-ChildItem *.ps1 | Unblock-File

# 2. Audit (read-only)
powershell -ExecutionPolicy Bypass -File .\ShackCleanup-Report.ps1

# 3. Review Report.html, edit the Action column in Findings.csv

# 4. Dry run, then the real thing
.\ShackCleanup-Act.ps1 -FindingsCsv C:\ShackCleanup\Report-<stamp>\Findings.csv -WhatIf
.\ShackCleanup-Act.ps1 -FindingsCsv C:\ShackCleanup\Report-<stamp>\Findings.csv

# 5. Reboot, then re-run the report to confirm
```

Full walkthrough: [docs/getting-started.md](docs/getting-started.md)

## What gets changed (with the default recommendations)

- **Microsoft 365 / Office:** Click-to-Run Office, MSI-based add-ins, classic and new Teams, OneDrive, Skype, the Office hub app, OneNote for Windows 10, the new Outlook, and Mail & Calendar. These are uninstalled for all users and removed from the provisioning image. Policies are then set so OneDrive and Teams don't reinstall themselves.
- **Telemetry:** diagnostic data is set to **Required** by policy, and the extras on top of that are turned off: the improvement-program tasks, advertising ID, activity history, Bing in Start search, the taskbar news feed, tailored experiences, silently installed "suggested" apps, and peer-to-peer upload of updates. The `DiagTrack` service is left **running**, because it carries the Required-level data itself.
- **Phones home / background updaters:** the Adobe updater and licensing check, Java updater, Intel Driver & Support Assistant, Intel Computing Improvement Program, NVIDIA telemetry, Edge startup boost, and launch-at-logon apps like Zoom, Dropbox, Spotify and Steam are all set to **Disable**. Browser updaters are set to **Keep**, because they deliver security fixes.
- **Station stability:** USB selective suspend is turned **off**, and Fast Startup is turned **off** so drivers fully re-initialize on every boot.
- **Third-party updates:** `winget upgrade` runs only for packages you mark **Upgrade**. Drivers and station software default to **Review**.

The details are in [docs/what-gets-changed.md](docs/what-gets-changed.md) and [docs/telemetry.md](docs/telemetry.md).

## Safety

- A **system restore point** is required. The Act script stops if it can't confirm one was created.
- **Registry exports** of every area it may touch are saved before any change.
- **`-WhatIf`** dry run shows every step without changing anything.
- **`ChangeLog.csv`** records each change with its old value, and `ShackCleanup-Undo.ps1` reverses it. You can undo selected items with `-FindingId`.
- **Uninstalls are not reversible** by the undo script. For those, use the restore point or reinstall.
- **OneDrive Known Folder Move check:** if your Desktop or Documents live in OneDrive, OneDrive removal is skipped until you move them back.

See [docs/safety-and-undo.md](docs/safety-and-undo.md).

## Requirements

- Windows 10 22H2 or Windows 11, with Windows PowerShell 5.1 (built in). PowerShell 7 isn't required.
- An administrator account.
- `winget` (the "App Installer" from the Microsoft Store) for third-party updates. Everything else works without it.
- System Protection enabled on the system drive. The Act script tries to enable it.

## Documentation

| Doc | Contents |
|---|---|
| [Getting started](docs/getting-started.md) | Step-by-step first run |
| [The report](docs/report.md) | Everything the audit collects and the files it writes |
| [Findings.csv reference](docs/findings-csv.md) | Every column, row type, and action value |
| [What gets changed](docs/what-gets-changed.md) | Exactly what the Act script does, in order |
| [Office 365 removal](docs/office365-removal.md) | How each Office/OneDrive/Teams flavor is removed, and the Known Folder Move gotcha |
| [Telemetry](docs/telemetry.md) | Each telemetry setting, what it does, and why DiagTrack stays on |
| [Classification rules](docs/classification-rules.md) | How items get flagged, the station-critical allowlist, and how to customize it |
| [Safety and undo](docs/safety-and-undo.md) | Restore points, change log, undo |
| [Troubleshooting](docs/troubleshooting.md) | Common problems and fixes |

## Disclaimer

These scripts uninstall software and change system policy. Read the report, run `-WhatIf`, and
keep a backup. They were written for a single-user station PC. On a machine that's managed by an
organization (domain, Intune, Group Policy), central policy may override or conflict with these
settings.

## License

[MIT](LICENSE)

73 de K2UA
