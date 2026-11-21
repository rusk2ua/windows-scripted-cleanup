# Changelog

## 1.2.0 - 2026-11-21

### Added
- **`ShackCleanup-NetCapture.ps1`:** checks on the wire that the cleanup worked. For a set time (default 4 hours) it records every outbound connection via Windows Filtering Platform auditing (event 5156), and every name looked up via the DNS Client log. Each connection is tied to its program, and `svchost` connections to the services in that process, for example `svchost (DiagTrack)`. Destinations are classified as Should be gone (Copilot, News/Bing/Widgets/ads, Office/OneDrive/Teams, activity history), Review, Expected (Required telemetry, Windows Update/Defender/Store, certificate checks, time, connectivity check, Edge updates, winget/GitHub) or LAN (including Tailscale). It also flags programs that shouldn't be running at all, such as OneDrive, Widgets, Phone Link, `CompatTelRunner` and `DeviceCensus`. Auditing, the Security log size and the DNS log setting are restored afterwards, including after Ctrl+C. `-NoConnectionAudit` samples TCP connections instead. See [docs/network-capture.md](docs/network-capture.md).
- Tests: 26 destination-classification cases, including MSN from Edge versus anything else. The case list is built so it can't flatten (the v1.0.1 bug, which turned up again while writing these tests).

## 1.1.3 - 2026-11-18

### Added: more Copilot removal
- **`Windows11AI`:** Copilot features inside the kept inbox apps are turned off: Paint's Cocreator, Generative Fill and Image Creator (`HKLM\...\CurrentVersion\Policies\Paint`), and Notepad's AI writing tools (`HKLM\SOFTWARE\Policies\WindowsNotepad\DisableAIFeatures`).
- **`Edge`:** `Microsoft365CopilotChatIconEnabled = 0`. Microsoft is making this the only control for Edge's Copilot toolbar button; the sidebar policy (`HubsSidebarEnabled`), which the scripts already set, no longer hides it on its own.

## 1.1.2 - 2026-11-18

### Fixed
- **Report:** Office scheduled tasks and services recommended `Remove` that are already disabled are now `Keep`. On the G10, the OneDrive tasks belonging to the disabled built-in Administrator account kept reappearing as actions.
- **Report:** Edge Game Assist is now `Review` instead of `Remove`. Edge reinstalls it during its own updates, so removing it just repeats every time.

## 1.1.1 - 2026-11-18

From the first Windows 11 run (GMKtec G10, Windows 11 Pro):

### Fixed
- **Act:** writes that Windows refuses even from an elevated session with a permissive key ACL (`UnauthorizedAccessException`) are now logged as `CHECK: Windows blocks scripts from setting this value...` instead of `FAILED`. On the G10 this hit the Widgets (`Dsh\AllowNewsAndInterests`) and News and Interests (`Windows Feeds\EnableFeeds`) policies. The likely cause is Windows' User Choice Protection driver; `gpedit.msc` can still set them.
- **Report:** the Windows 10-only News and Interests row is no longer offered on Windows 11, and the Widgets policy row only appears while the Widgets app is installed. Removing the app is what actually gets rid of Widgets.
- **Act:** a Store app that's already gone now logs `OK (already gone)` instead of `OK`.

## 1.1.0 - 2026-11-17

### Added: Windows 11 support
The report detects Windows 11 (build 22000 or later) and adds rows in four new categories. See [docs/windows-11.md](docs/windows-11.md).
- **`WindowsApps`:** preinstalled Store apps set to Remove: Copilot, Clipchamp, News, Weather, Bing Search, Widgets, Tips, Get Help, Feedback Hub, Maps, Solitaire, Sticky Notes, Journal, Power Automate, Dev Home, Family, Movies & TV, Phone Link, the Xbox apps and Game Bar, and Edge Game Assist. Media Player and Quick Assist are set to Review. Calculator, Notepad, Paint, Photos, Snipping Tool, Terminal, Camera, Sound Recorder, Clock, the Store, App Installer and framework packages are never listed. Packages Windows marks non-removable become `Keep`.
- **`Windows11AI`:** Copilot off by policy (user and machine), no Copilot taskbar button, Recall snapshots off and Recall locked out, Click to Do off.
- **`Windows11UI`:** Widgets and the Chat icon off; Start tips, ads, account notifications and recently added apps off (recent files and jump lists set to Review); no search highlights or Bing web results; File Explorer opens to This PC, with Home, Gallery, sync-provider ads and Office.com files hidden; no suggested content in Settings, tips notifications, post-update welcome, "finish setting up" nag or lock-screen tips; no cloud-optimized content or Microsoft account nags.
- **`Edge`** (Windows 10 and 11): no startup boost or background mode, no sidebar or Copilot button, no shopping assistant, first-run or recommendation nags, personalization reporting or MSN new-tab feed, and diagnostic data at Required.

### Changed
- Microsoft To Do, People, News and Weather now default to Remove instead of Review.
- `Report.html` shows every category, the new ones included.
- The station-critical allowlist adds GH Everyware, wfview and remkey.
- The 45-day "no Windows update" warning mentions ESU only on Windows 10.
- **Act:** registry backups now include the Explorer, Search and user-engagement keys and the Explorer namespace CLSIDs. After a run that changed per-user settings, it reminds you to sign out and back in.

## 1.0.6 - 2026-11-11

### Fixed
- **Per-user winget packages are no longer upgraded or removed from an admin session.** Slack's per-user install was left broken by an elevated upgrade: its launcher and updater were removed, and the new version was never put in place. Zoom's uninstall was refused for the same reason.
  - **Report:** checks each package with an update using `winget list --id <id> --exact --scope user`. Per-user packages get `scope=user` in `State`, are recommended `Review`, and the note gives the exact non-admin command.
  - **Act:** before every winget upgrade or uninstall, the script skips any row tagged `scope=user`, and it also re-checks the scope live, which protects older `Findings.csv` files. Skipped rows are logged as `SKIPPED: per-user install - in a NON-admin PowerShell run: ...`.

## 1.0.5 - 2026-11-11

### Fixed
- **Report:** items that were already in their target state were still recommended for action, so a second run of the Act script selected dozens of rows that only logged `OK (already)`. This covered disabled tasks, disabled startup entries, disabled services, and Office/OneDrive/Teams policy values that were already set. These rows are now recommended `Keep`, with an "Already disabled" or "Already set" note, so re-runs only select what's actually left to do.

## 1.0.4 - 2026-11-11

### Fixed
- **Act / AppX:** `Remove-AppxPackage -AllUsers` fails with `0x80070002` when a stale or deleted user profile still has the package registered. The script now falls back to removing the package user by user. The result names any account that still has it, and reports a registration left behind by a deleted account (a SID that won't resolve to an account name) as OK with a note rather than a failure.
- **Act / winget:**
  - Every call now uses `--source <source from the report>` (normally `winget`), so winget no longer searches the Microsoft Store source. That search is where transient DNS failures (`0x80072EE7`) were happening.
  - Rows whose installed version is `Unknown` get `--include-unknown`.
  - Network errors are retried once after 15 s.
  - Known winget exit codes now come with a plain-English hint in `ChangeLog.csv`, including the fix for per-user installs that can't be removed from an admin session (`0x8A15007D`).

## 1.0.3 - 2026-11-11

### Fixed
- **Act:** `Stop-Transcript -WhatIf:$false` threw "parameter cannot be found" on Windows PowerShell 5.1, where only `Start-Transcript` accepts `-WhatIf`. It's now a plain `Stop-Transcript` inside `try/catch`.

## 1.0.2 - 2026-11-11

### Fixed
- **Act:** `Action = Remove` on a winget (Updates) row was counted in the summary but never carried out, and nothing was logged. It now runs `winget uninstall --id <id> --exact --silent`, before the upgrades.
- **Act:** under `-WhatIf` the transcript was also only simulated, so the final `Stop-Transcript` threw an error. The transcript is now always recorded.

### Added
- **Act:** a final check lists and logs (`NOT HANDLED`) any selected row whose Type/Action combination no step supports, instead of ignoring it.

## 1.0.1 - 2026-11-11

### Fixed
- **Report:** telemetry registry rows were written to `Findings.csv` as single characters, for example `Name = D`, `Detail = i`. A PowerShell array-of-arrays literal was being flattened. The Act script then logged 58 `FAILED: bad Detail format` lines. **Re-run the report to regenerate `Findings.csv`**; a CSV from v1.0.0 can't be fixed by hand.
- **Act:** `-WhatIf` no longer prints `What if: Set Alias gcim...` noise from module auto-loading.
- **Act:** Registry rows are now checked for a real `HKLM:\` / `HKCU:\` path, with a clear message if the CSV is stale.

### Changed
- Station-critical allowlist now includes DXLog.net, HDSDR, SDR#, SDR Console, SDRuno and SDR-Radio. Their winget updates default to `Review` instead of `Upgrade`.

## 1.0.0 - 2026-11-11

Initial release.

- `ShackCleanup-Report.ps1`: read-only audit of hardware, station health, Office 365 / OneDrive / Teams, startup items, scheduled tasks, services, telemetry settings, outbound connections, and winget updates. Writes `Findings.csv` and `Report.html`.
- `ShackCleanup-Act.ps1`: applies approved actions, with a mandatory restore point, registry exports, `-WhatIf`, and `ChangeLog.csv`.
- `ShackCleanup-Undo.ps1`: reverses registry, startup, scheduled-task, service, and power changes from `ChangeLog.csv`.
- Station-critical allowlist for common ham radio logging, digital-mode, rig-control, USB-serial, audio-routing, rotator, and time-sync software.
