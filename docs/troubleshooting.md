# Troubleshooting

### "Running scripts is disabled on this system"
Run through `powershell -ExecutionPolicy Bypass -File .\Script.ps1`, or allow local scripts for
your user: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. Also run
`Get-ChildItem *.ps1 | Unblock-File` once after downloading.

### "Run this from an elevated PowerShell window"
Right-click Windows PowerShell and choose **Run as administrator**.

### The report warns that the elevated account differs from the console user
You elevated with a different admin account. Per-user items (HKCU Run entries, OneDrive, classic
Teams, per-user telemetry settings) will be read from and applied to that account, not to the one
you use at the station. Log in as your station user and elevate from there. If your station user
isn't an admin, temporarily make it one.

### "Could not confirm a new restore point"
- Open `sysdm.cpl`, go to the *System Protection* tab, select the system drive, choose *Configure*, and turn it on with a few GB of space.
- Check that the *Volume Shadow Copy* service isn't disabled.
- Then re-run. Use `-SkipRestorePoint` only if you have another full backup.

### winget section says the module failed / `WingetRaw.txt` was written
- Installing a module needs internet access to the PowerShell Gallery. Check proxy and firewall rules.
- In Windows PowerShell 5.1, TLS 1.2 may be needed. The script sets it, but some old .NET builds still fail. Update .NET Framework, or install the module by hand: `Install-Module Microsoft.WinGet.Client -Scope CurrentUser`.
- If `winget` itself is missing, update **App Installer** from the Microsoft Store.

### An uninstall shows `CHECK (exit N)`
- Office Click-to-Run: open *Settings > Apps* and see whether it's still listed. If it is, run Microsoft's Office uninstall troubleshooter, or the Office Deployment Tool with a `<Remove All="TRUE"/>` configuration.
- MSI exit `1603`: generic failure. See `%TEMP%\MSI*.log`, or retry after a reboot.
- MSI exit `1618`: another install was running. Reboot and re-run. Already-removed items log as `OK (already gone)`.

### Store app removal shows `0x80070002`
`Remove-AppxPackage -AllUsers` trips over a package registration that belongs to a stale or deleted user profile. Since v1.0.4 the script falls back to removing the package user by user and says who still has it. A registration left behind by a **deleted account** can't be removed, and it's harmless: no one can launch it.

### winget: "The package installed for user scope cannot be uninstalled when running with administrator privileges"
The app was installed per-user, Zoom being the usual example. Open a **normal, non-admin** PowerShell and run `winget uninstall --id <Id> -e`.

### A per-user app (Slack, Zoom, ...) won't launch after an upgrade
Versions before 1.0.6 could upgrade per-user apps from the elevated session, which can leave a Squirrel-style install (Slack, Teams classic, Discord) with no launcher. Your data in `%APPDATA%\<App>` is untouched. To repair it:
1. Close the app, then `Rename-Item "$env:LOCALAPPDATA\<app>" "<app>.broken"`.
2. In a **non-admin** PowerShell: `winget install --id <Id> -e --source winget --scope user --force`.
3. Check that it opens signed in, then delete the `.broken` folder.

### winget: "Installer failed with exit code: 1223"
1223 means the installer was cancelled, usually because the app was running. Quit it (check the system tray), then run `winget upgrade --id <Id> -e`.

### winget: `0x80072EE7` / "server name or address could not be resolved"
A DNS hiccup while winget was contacting its package source. Since v1.0.4 the script only uses the `winget` source and retries once. If it still fails, check your connection and re-run.

### OneDrive was skipped
That's the Known Folder Move blocker. See [office365-removal.md](office365-removal.md#onedrive-known-folder-move-the-gotcha).

### Something re-appeared after a Windows feature update
Feature updates can restore inbox apps and reset some settings. Re-run the report and act on the
new findings. The anti-reinstall policies usually survive.

### A radio, rotator, or audio device misbehaves after running
1. Check the COM-port list in the new `Report.html` against the old one.
2. If you disabled a startup item, task or service you didn't recognize, undo just that one: `.\ShackCleanup-Undo.ps1 -ChangeLog ... -FindingId <Id>`.
3. Still stuck? Roll back with the restore point (`rstrui.exe`).
4. Open an issue with the `Findings.csv` row and the item's publisher, so the station-critical allowlist can be extended.

### Settings show "Some settings are managed by your organization"
That's expected. Policy-based settings, like the telemetry ones, always show that message.

### The report takes a long time
Usually it's reverse DNS on many connections, or winget catalog refresh. Use `-SkipConnections`,
or lower `-ConnectionSamples`.
