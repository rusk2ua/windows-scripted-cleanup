# What gets changed (`ShackCleanup-Act.ps1`)

## Parameters

| Parameter | Effect |
|---|---|
| `-FindingsCsv <path>` | **Required.** The `Findings.csv` you reviewed. |
| `-WhatIf` | Dry run. Every step prints `What if: ...` and nothing changes. The log goes to `WhatIf-<stamp>\`. |
| `-Yes` | Skip the "type YES" prompt |
| `-Force` | Remove OneDrive even if Known Folder Move is active. **Not recommended.** |
| `-SkipRestorePoint` | Continue if a restore point can't be confirmed. **Not recommended.** |
| `-Verbose` | More detail |

## Order of operations

The order matters. Each step depends on the ones before it.

### 0. Safety net (skipped under `-WhatIf`)

1. Enable System Protection on the system drive, if it's off.
2. Temporarily set `SystemRestorePointCreationFrequency = 0` so Windows doesn't skip the restore point because another one was made in the last 24 hours. The original value is put back afterward.
3. `Checkpoint-Computer -Description "ShackCleanup <stamp>"`, then confirm a new restore point actually exists. **If it doesn't, the script stops** unless you passed `-SkipRestorePoint`.
4. `reg export` the Run keys, the `StartupApproved` keys, `HKLM\SOFTWARE\Policies`, `HKCU\Software\Policies`, `ContentDeliveryManager`, `Privacy`, `AdvertisingInfo`, and `Session Manager\Power` into `RegistryBackup\`.

### 1. Disable startup items, tasks and services

Rows with `Action = Disable` of type `RunKey`, `StartupFolder`, `ScheduledTask` or `Service`.
Office365 *services and tasks* aren't touched yet; see step 5.

### 2. Stop Office-family processes

Word, Excel, PowerPoint, Outlook, OneNote, Access, Publisher, Lync, OneDrive, Teams and Skype are
force-closed. This only happens if at least one Office365 `Remove` row is selected.

### 3. Uninstall

1. **Click-to-Run Office (Microsoft 365 Apps).** Main products first, language packs after. Each one waits until its uninstall entry is gone (up to 30 min).
2. **MSI products.** Teams Machine-Wide Installer, the Teams Meeting Add-in, and older Office components.
3. **Classic Teams**, the per-user install.
4. **OneDrive.** Skipped while Known Folder Move is active.
5. **Other installers.** Classic Skype, and add-ins with their own uninstaller.

Exit codes `0`, `3010` (reboot required) and `1605` (already gone) are logged as `OK`. Anything
else is logged as `CHECK (exit N)`, so look at those after the run.

### 4. Store (AppX) apps

Each selected package is removed for **all users**, and from the **provisioning image** so new
user accounts don't get it.

### 5. Office leftovers

Office scheduled tasks and services that survived the uninstall are disabled. Usually there's
nothing left by this point, and the log shows `OK (not present)`.

### 6. Registry, policy and power

- Telemetry and privacy values ([telemetry.md](telemetry.md))
- OneDrive and Teams anti-reinstall policies ([office365-removal.md](office365-removal.md))
- Fast Startup off (`HiberbootEnabled = 0`)
- USB selective suspend off (AC and DC) on the active power scheme

Each change logs the old value's type and data, or `<absent>` if it didn't exist, so undo can put
it back exactly.

### 7. winget removals and upgrades

The script first uninstalls rows with `Action = Remove` (`winget uninstall --id ... --exact --silent`), then upgrades rows with `Action = Upgrade`, one package at a time. If `winget.exe` isn't on the
PATH in the elevated session, the script looks in `WindowsApps` for the App Installer copy.

### 8. Unhandled-row check

Any selected row that no step acted on (an Action the row's Type doesn't support) is listed in a
warning and logged as `NOT HANDLED`. An instruction is never silently ignored.

## Output

```
Report-<stamp>\
  Findings.csv
  Act-<stamp>\
    ChangeLog.csv      <- every change, old/new values, result
    RegistryBackup\    <- .reg exports from before
    Transcript.txt
```

`ChangeLog.csv` columns: `Time, FindingId, Kind, Target, Property, OldValue, NewValue, Result, Reversible`.

`Result` values:

| Value | Meaning |
|---|---|
| `OK` | Done |
| `OK (already ...)` | Was already in the target state |
| `OK (not present)` | The item no longer exists |
| `OK (exit N)` | The uninstaller succeeded |
| `CHECK ...` | Finished, but with something worth a look |
| `SKIPPED: ...` | Deliberately skipped, for example because of Known Folder Move |
| `FAILED: ...` | The error message follows |
| `NOT HANDLED: ...` | That Action isn't supported for that row Type |
| `WhatIf` | Dry run |

## What it never does

- Doesn't touch drivers, unless you mark a winget driver package `Upgrade`
- Doesn't touch Windows Update, Defender, or the Windows Firewall
- Doesn't disable `DiagTrack` unless you set its Action yourself
- Doesn't delete Run entries, shortcuts or task definitions. It disables them.
- Doesn't delete your OneDrive folder or any of its files
