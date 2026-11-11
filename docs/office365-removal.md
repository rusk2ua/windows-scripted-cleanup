# Office 365 / OneDrive / Teams removal

Microsoft ships Office-related software in several different forms, often more than one on the
same PC. The report finds each one, and the Act script removes each one the way it was installed.

## What's covered

| Component | How it's installed | How it's removed |
|---|---|---|
| Microsoft 365 Apps / Office 2016-2024 (Word, Excel, Outlook...) | Click-to-Run | Its own `OfficeClickToRun.exe ... productstoremove=...` uninstall string, plus `DisplayLevel=False` for a silent run |
| Office language packs / proofing | Click-to-Run | Same; usually removed along with the main product |
| Teams Machine-Wide Installer | MSI | `msiexec /x {GUID} /qn` |
| Teams Meeting Add-in for Office | MSI | `msiexec /x {GUID} /qn` |
| Classic Teams (work or school) | Per-user Squirrel | `Update.exe --uninstall -s` |
| New Teams (`MSTeams`) / consumer Teams (`MicrosoftTeams`) | Store (AppX) | `Remove-AppxPackage -AllUsers` and deprovision |
| OneDrive | Per-user or per-machine EXE | `OneDriveSetup.exe /uninstall` (`/allusers` for per-machine) |
| Office hub ("Microsoft 365" app) | AppX | Remove and deprovision |
| OneNote for Windows 10 | AppX | Remove and deprovision |
| New Outlook | AppX | Remove and deprovision |
| Mail and Calendar | AppX | Remove and deprovision |
| Skype (app / classic) | AppX / Inno Setup | Remove / `unins000.exe /VERYSILENT` |
| Office scheduled tasks (`\Microsoft\Office\...`) | Task Scheduler | Usually removed by the uninstall; disabled if any are left |
| `ClickToRunSvc` | Service | Usually removed by the uninstall; disabled if it's left |

Microsoft To Do and People sync with a Microsoft account and default to **Review**.

## Keeping it gone

Three policy rows are added to `Findings.csv`, defaulting to **Apply**:

| Setting | Value | Effect |
|---|---|---|
| `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC` | `1` | OneDrive can't sync, even if something reinstalls it |
| `HKCU\Software\Classes\CLSID\{018D5C66-...}\System.IsPinnedToNameSpaceTree` | `0` | Removes the OneDrive entry from File Explorer's navigation pane |
| `HKLM\SOFTWARE\Microsoft\Office\Teams\PreventInstallationFromMsi` | `1` | Stops the Teams machine-wide installer from coming back |

The telemetry section also sets `SilentInstalledAppsEnabled = 0`, which stops Windows from
silently installing "suggested" apps, a route by which Store apps sometimes reappear.

Feature updates (for example a Windows 11 upgrade) can bring some inbox apps back. Re-run the
report after any feature update.

## OneDrive Known Folder Move (the gotcha)

If OneDrive's "PC folder backup" has ever been turned on, your **Desktop, Documents and
Pictures** may physically live in `C:\Users\<you>\OneDrive\...`. Uninstalling OneDrive at that
point leaves those folders pointing into an orphaned OneDrive directory, which is confusing at
best.

The report checks `User Shell Folders` and adds a **Blocker** row if any of them point into
OneDrive. While that row exists, the Act script **skips the OneDrive uninstall**. Everything else
still runs.

To fix it before removing OneDrive:

1. Click the OneDrive cloud icon in the system tray, then *Settings > Sync and back up > Manage back up*.
2. Turn off backup for each folder. When asked, choose to keep the files on this PC.
3. Check that the files are back in `C:\Users\<you>\Desktop`, `Documents` and `Pictures`. Copy over anything that stayed in the OneDrive folder.
4. Re-run the report. The Blocker row should be gone.

Your OneDrive **folder and files are never deleted** by these scripts. Only the sync client is
removed. Delete the folder yourself once you've confirmed nothing in it is needed.

## Your Microsoft account

Removing the apps doesn't remove a Microsoft account sign-in from Windows. If you sign in to
Windows with a Microsoft account, it stays that way. That's also how the free Windows 10 Extended
Security Updates enrollment works, so leave the Windows sign-in alone unless you know your ESU
status won't be affected.
