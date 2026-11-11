# Getting started

This walks through a first run on a station PC from start to finish. Plan on about 30 minutes,
most of it spent reading the report. Don't do this the night before a contest.

## 1. Before you start

- **Close your logging and radio-control software.** That means N1MM+, WSJT-X, OmniRig, DXLab and the like. The report doesn't need them closed, but the Act script stops Office-family processes and may run installers.
- **Check Windows Update.** Open *Settings > Update & Security > Windows Update*. On Windows 10, make sure it says the PC is enrolled in Extended Security Updates. If it isn't, sort that out first, because an unpatched OS is a bigger problem than anything these scripts clean up.
- **Back up anything important.** The scripts make a restore point, but a restore point isn't a backup.

## 2. Get the scripts onto the PC

Clone or download the repo into a folder such as `C:\ShackCleanup`:

```powershell
git clone https://github.com/rusk2ua/windows-scripted-cleanup.git C:\ShackCleanup
```

Or download the ZIP from GitHub and extract it there.

## 3. Open an elevated PowerShell window

Start menu > type `PowerShell` > right-click **Windows PowerShell** > **Run as administrator**.

Use **the same Windows account you normally use at the station**. Per-user items (things that
start at your logon, OneDrive, classic Teams) are read from, and changed for, the account that's
elevated. If you elevate with a different admin account, the report warns you.

```powershell
cd C:\ShackCleanup
Get-ChildItem *.ps1 | Unblock-File   # clears the "downloaded from the internet" flag
```

## 4. Run the report

```powershell
powershell -ExecutionPolicy Bypass -File .\ShackCleanup-Report.ps1
```

`-ExecutionPolicy Bypass` applies only to this one run and doesn't change your system policy.

The report takes 1-3 minutes, mostly winget and the 20-second connection sampling. When it
finishes, it opens `Report.html` and prints the path to `Findings.csv`, for example:

```
C:\ShackCleanup\Report-20261111-070512\Findings.csv
```

Useful switches:

| Switch | Effect |
|---|---|
| `-NoModuleInstall` | Don't install the WinGet PowerShell module; use raw `winget upgrade` text instead |
| `-SkipConnections` | Skip the outbound-connection sampling |
| `-ConnectionSamples 6` | Take more connection snapshots (10 s apart) |
| `-OutRoot D:\Audits` | Write reports somewhere other than `C:\ShackCleanup` |

## 5. Review

Start with `Report.html`. It's grouped by category: Office365, Telemetry, Startup,
ScheduledTask, Service, StationTuning, and Updates. Pay attention to:

- **Rows flagged `Blocker`:** for example, OneDrive Known Folder Move. See [office365-removal.md](office365-removal.md).
- **Rows recommended `Review`:** the script didn't want to decide these for you. Examples are remote-access tools, peripheral helpers, third-party antivirus, generic updaters, driver updates, and updates to station software.
- **The "Outbound connections" section:** anything talking to the internet that you don't recognize.

Then edit `Findings.csv`:

- The **Action** column is what the Act script reads. It comes pre-filled with the recommendation when that's Disable, Remove, Apply or Upgrade, and blank otherwise.
- **Blank** means leave it alone.
- Don't change the other columns. The Act script uses `Type`, `Location`, `ItemName` and `Detail` to find each item.

If Office is already gone, use Notepad, or Google Sheets: *File > Import > Upload*, then
*File > Download > Comma-separated values*. Keep the header row and the `Id` column.

Column and value reference: [findings-csv.md](findings-csv.md).

## 6. Dry run

```powershell
.\ShackCleanup-Act.ps1 -FindingsCsv C:\ShackCleanup\Report-<stamp>\Findings.csv -WhatIf
```

This prints every step and writes a `WhatIf-<stamp>\ChangeLog.csv` with `Result = WhatIf` on
each row. Nothing changes and no restore point is created.

## 7. Apply

```powershell
.\ShackCleanup-Act.ps1 -FindingsCsv C:\ShackCleanup\Report-<stamp>\Findings.csv
```

Type `YES` at the prompt, or pass `-Yes` to skip it. The Office uninstall is the slow part and can
take 5-20 minutes. Output lands in `Report-<stamp>\Act-<stamp>\`:

- `ChangeLog.csv`: every change, with its old and new value and the result
- `RegistryBackup\*.reg`: exports taken before anything changed
- `Transcript.txt`: the full console output

## 8. Reboot and verify

Reboot, then run the report again. Office365 rows should be gone, telemetry rows should show
`Keep (Already set)`, and disabled items should show `State = Disabled`.

Then check the station itself: rig control on every radio, audio codecs, keying, rotator control,
and time sync.

## If something's wrong

- **A single setting:** `.\ShackCleanup-Undo.ps1 -ChangeLog <path>\ChangeLog.csv -FindingId 42`
- **Everything reversible:** `.\ShackCleanup-Undo.ps1 -ChangeLog <path>\ChangeLog.csv`
- **Worst case:** `rstrui.exe`, then pick the `ShackCleanup <stamp>` restore point.

See [safety-and-undo.md](safety-and-undo.md) and [troubleshooting.md](troubleshooting.md).
