# Safety and undo

There are three layers. Use the lightest one that does the job.

## Layer 1: `ShackCleanup-Undo.ps1` (targeted)

This reverses changes recorded in `ChangeLog.csv`. It only touches rows with `Result = OK` and
`Reversible = True`, working through them newest first.

```powershell
# Preview
.\ShackCleanup-Undo.ps1 -ChangeLog C:\ShackCleanup\Report-<stamp>\Act-<stamp>\ChangeLog.csv -WhatIf

# Undo everything reversible
.\ShackCleanup-Undo.ps1 -ChangeLog ...\ChangeLog.csv

# Undo only specific findings (Id column from Findings.csv)
.\ShackCleanup-Undo.ps1 -ChangeLog ...\ChangeLog.csv -FindingId 14,27
```

| Change kind | How it's reversed |
|---|---|
| `Registry` | The old value is restored with its original type (DWord, QWord, String, ExpandString, MultiString, Binary), or deleted if it didn't exist before |
| `StartupApproved` (startup items) | The old marker is restored, or deleted, which re-enables the item |
| `ScheduledTask` | `Enable-ScheduledTask` |
| `Service` | The original start mode is restored, including Automatic (Delayed Start) via `sc.exe config start= delayed-auto`. Automatic services are started again. |
| `PowerCfg` | The original AC and DC values go back on the active scheme |

Not reversible here: uninstalls, AppX removals, and winget upgrades.

## Layer 2: registry exports

`Act-<stamp>\RegistryBackup\*.reg` holds exports of the touched areas, taken before any change.
Double-click one (or `reg import file.reg`) to merge it back. That restores values but doesn't
delete values the script added. For that, use Layer 1.

## Layer 3: system restore point

The Act script won't continue without one, unless you pass `-SkipRestorePoint`. To roll back the
whole system, including uninstalls:

1. Run `rstrui.exe`.
2. Choose *Choose a different restore point*, then **ShackCleanup <stamp>**.
3. Reboot when prompted.

Restore points cover system files, installed programs and the registry. They don't cover your
personal files.

## Reinstalling something you removed

- **Office:** sign in at office.com and reinstall, or use the Office Deployment Tool.
- **OneDrive:** `winget install Microsoft.OneDrive`. Delete the `DisableFileSyncNGSC` policy first, either with Undo using its `FindingId` or by deleting the value by hand.
- **Teams:** `winget install Microsoft.Teams`. Remove `PreventInstallationFromMsi` first if you need the machine-wide installer.
- **Store apps:** reinstall from the Microsoft Store.
