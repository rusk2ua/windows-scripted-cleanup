# Changelog

## 1.0.0 - 2026-11-11

Initial release.

- `ShackCleanup-Report.ps1`: read-only audit of hardware, station health, Office 365 / OneDrive / Teams, startup items, scheduled tasks, services, telemetry settings, outbound connections, and winget updates. Writes `Findings.csv` and `Report.html`.
- `ShackCleanup-Act.ps1`: applies approved actions, with a mandatory restore point, registry exports, `-WhatIf`, and `ChangeLog.csv`.
- `ShackCleanup-Undo.ps1`: reverses registry, startup, scheduled-task, service, and power changes from `ChangeLog.csv`.
- Station-critical allowlist for common ham radio logging, digital-mode, rig-control, USB-serial, audio-routing, rotator, and time-sync software.
