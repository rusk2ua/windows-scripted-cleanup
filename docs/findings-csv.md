# Findings.csv reference

`Findings.csv` connects the report to the Act script. The Act script only reads rows whose
**Action** is one of `Disable`, `Remove`, `Apply` or `Upgrade`.

## Columns

| Column | Meaning | Edit it? |
|---|---|---|
| `Id` | Row number. Used by `ShackCleanup-Undo.ps1 -FindingId`. | No |
| `Category` | `Office365`, `Telemetry`, `Startup`, `ScheduledTask`, `Service`, `StationTuning`, or `Updates` | No |
| `Type` | How the item is found and acted on (see below) | No |
| `Name` | Human-readable name | No |
| `Location` | Where the item lives: a Run-key or startup-folder code, a task path, or an uninstall registry path | No |
| `ItemName` | The exact key: value name, file name, task name, service name, product code, AppX name, or winget ID | No |
| `Detail` | Command line, uninstall string, or `Path\|Name\|Type\|Value` for registry rows | No |
| `Company` | Publisher from the executable's version info | No |
| `State` | Current state when the report ran | No |
| `Flag` | `StationCritical`, `O365`, `PhonesHome`, `Updater`, `Updater/PhonesHome`, `Startup`, `RemoteAccess`, `Security`, `Stability`, `Update`, `Blocker`, `Info` | No |
| `Recommendation` | What the report suggests: `Disable`, `Remove`, `Apply`, `Upgrade`, `Review`, `Keep`, or `Skip` | No |
| **`Action`** | **What will actually happen.** Pre-filled from the recommendation when it's actionable. | **Yes** |
| `Note` | Why the item was flagged | No |

## Row types and what each Action does

| Type | Valid Action | What the Act script does | Reversible by Undo? |
|---|---|---|---|
| `RunKey` | `Disable` | Writes the "disabled" marker to the matching `StartupApproved` key, the same thing Task Manager's *Disable* button does. The Run entry itself is not deleted. | Yes |
| `StartupFolder` | `Disable` | Same, using `StartupApproved\StartupFolder`. The shortcut file stays. | Yes |
| `ScheduledTask` | `Disable` (Office rows: `Remove`) | `Disable-ScheduledTask`. Office rows are handled after the uninstall, in case the uninstaller already removed them. | Yes |
| `Service` | `Disable` (Office rows: `Remove`) | `Stop-Service`, then `Set-Service -StartupType Disabled`. Office rows are handled after the uninstall, because the Click-to-Run service has to be running for the uninstall to work. | Yes |
| `Uninstall-C2R` | `Remove` | Runs the product's `OfficeClickToRun.exe` uninstall string with `DisplayLevel=False`, then waits up to 30 min for the entry to disappear. Main products go before language packs. | No |
| `Uninstall-MSI` | `Remove` | `msiexec /x {ProductCode} /qn /norestart` | No |
| `Uninstall-TeamsClassic` | `Remove` | `%LOCALAPPDATA%\Microsoft\Teams\Update.exe --uninstall -s` | No |
| `Uninstall-OneDrive` | `Remove` | `OneDriveSetup.exe /uninstall`, adding `/allusers` for per-machine installs. **Skipped if Known Folder Move is active** unless you pass `-Force`. | No |
| `Uninstall-Exe` | `Remove` | Runs the quiet uninstall string if there is one, otherwise the normal one. Inno Setup uninstallers get `/VERYSILENT`. | No |
| `Appx` | `Remove` | `Remove-AppxPackage -AllUsers` and `Remove-AppxProvisionedPackage -Online` | No |
| `Registry` | `Apply` | Sets the value given in `Detail` (`Path\|Name\|Type\|Value`), creating the key if needed | Yes |
| `PowerCfg` | `Apply` | `powercfg /setacvalueindex` and `/setdcvalueindex` on the active scheme, then `/setactive` | Yes |
| `Winget` | `Upgrade` or `Remove` | `Upgrade`: `winget upgrade --id <ItemName> --exact --silent ...`. `Remove`: `winget uninstall --id <ItemName> --exact --silent`. Removals run before upgrades. | No |
| `Check` | (none) | Information only. `Blocker` rows change what the Act script does (see Office 365 removal). | n/a |

A blank Action, or any word other than the four action words, means leave it alone. If you use one of the four action words on a row type that doesn't support it (for example `Disable` on a Registry row), the Act script prints a **NOT HANDLED** warning and logs it, rather than ignoring it silently.

## Recommendation values

| Value | Meaning |
|---|---|
| `Disable` | Safe to stop from running. Pre-filled. |
| `Remove` | Uninstall or remove. Pre-filled. |
| `Apply` | Set a registry, policy or power value. Pre-filled. |
| `Upgrade` | A newer version is available through winget. Pre-filled. |
| `Review` | A judgment call. Action is left blank so you decide. |
| `Keep` | Leave alone. Station-critical, a browser security updater, or already set. |
| `Skip` | A winget update for something that's being removed anyway |

## Editing tips

- To keep something, blank its Action, or set it to anything that isn't one of the four action words (for example `Keep`).
- To act on a `Review` row, type the action into Action, for example `Disable` for a `TeamViewer` service you don't use.
- Don't reorder or delete columns. Deleting **rows** is fine.
- Save as plain CSV. If you use Google Sheets, download it as *Comma-separated values*.
