# Changelog

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
