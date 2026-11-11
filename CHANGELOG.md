# Changelog

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
