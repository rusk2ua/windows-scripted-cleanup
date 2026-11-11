# Classification rules

Each startup item, task and service is classified by matching its **name + command line +
publisher** against three sets of rules, in this order. The first match wins.

1. **Station-critical allowlist:** `Keep`, never actioned
2. **Office 365 pattern:** `Remove` (or `Disable` for startup entries)
3. **Specific vendor rules:** see the table below
4. **No match:** `Info` / `Keep`. Stock Microsoft items with no match are left out of the report entirely.

All three live near the top of `ShackCleanup-Report.ps1` as `$StationPattern`, `$O365Pattern`
and `$Rules`.

## 1. Station-critical allowlist (`$StationPattern`)

Anything matching these is tagged `StationCritical` / `Keep`:

| Area | Matches |
|---|---|
| Logging / contesting | N1MM, Win-Test, DXLab (Commander, DXKeeper, SpotCollector), Log4OM, Ham Radio Deluxe / HRD, RUMlog, N3FJP |
| Digital modes | WSJT-X, JTDX, JTAlert, GridTracker, fldigi, flrig, MMTTY, 2Tone, skimmer software |
| Rig control / radios | OmniRig, FlexRadio / SmartSDR, Icom (RS-BA1, RS-MS1), Elecraft, Yaesu, Kenwood |
| Interfaces / SO2R | microHAM, SO2R, OTRSP, RemoteRig, WinKey / K1EL |
| USB-serial / virtual ports | FTDI, Silicon Labs / CP210x, Prolific, VSPE, com0com, "virtual serial" |
| Audio routing | VB-Audio, Voicemeeter, Realtek audio (`RtkAudUService`) |
| Rotators | PstRotator, SPID, Green Heron |
| Time sync | Meinberg NTP, `ntpd`, Dimension 4, BktTimeSync, NetTime |
| QSL | TQSL / TrustedQSL, LoTW |

The same allowlist also stops winget from auto-upgrading station software: matching packages get
`Review` instead of `Upgrade`.

## 2. Office 365 pattern (`$O365Pattern`)

Click-to-Run, "Microsoft Office", "Microsoft 365", Office 16, Office update and telemetry tasks,
OneDrive, Teams, MSTeams, Skype, Outlook, OneNote, the Office hub. Uninstall entries for Visual
C++, .NET, Edge, Update Health Tools, GameInput and the Windows SDK are excluded.

## 3. Vendor rules (`$Rules`)

| Pattern (summary) | Flag | Default | Why |
|---|---|---|---|
| `MicrosoftEdgeAutoLaunch_*` | Startup | Disable | Edge startup boost preloads Edge at logon |
| Adobe ARM, Adobe Genuine (AGS), AdobeGC, CCXProcess, Acrobat update | Updater/PhonesHome | Disable | Background updater and license checks |
| Google Update / GoogleUpdater / Chrome update | Updater | Keep | Browser security |
| Edge Update | Updater | Keep | Browser security |
| Mozilla Maintenance / Firefox background update | Updater | Keep | Browser security |
| Brave / Opera updaters | Updater | Keep | Browser security |
| Intel `ESRV`, `QueenCreek`, `SystemUsageReport`, Computing Improvement, SUR QC | PhonesHome | Disable | Intel Computing Improvement Program telemetry |
| Intel Driver & Support Assistant (`DSAService`, `DSAUpdateService`) | Updater/PhonesHome | Disable | Polls Intel continuously; run it by hand when you want it |
| `jusched`, Java update | Updater | Disable | |
| NVIDIA telemetry | PhonesHome | Disable | |
| Zoom, Dropbox, Spotify, Steam, Discord, Epic, iTunes / Apple Software Update, CCleaner, Wallpaper Engine | Startup | Disable | Launch-at-logon apps that check in with their vendor |
| TeamViewer, AnyDesk, Splashtop, RustDesk, Chrome Remote Desktop, Parsec, NoMachine | RemoteAccess | **Review** | Keep if you use it to reach the shack |
| Logitech, Razer, Corsair iCUE, SteelSeries | Startup | Review | Peripheral helpers |
| Avast, AVG, McAfee, Norton, Webroot, Kaspersky | Security | Review | Third-party AV |
| *anything* with "update", "updater", "updatetask" | Updater | Review | Generic; ignored for Microsoft-signed items |
| *anything* with "telemetry", "ceip", "usage report", "analytics" | PhonesHome | Review | Generic; ignored for Microsoft-signed items |

The two generic rules never pull in Microsoft-signed items. That's why Windows Update
(`wuauserv`), Update Orchestrator and the like don't appear.

## Customizing

- **Add your own station software:** add a term to `$StationPattern`. It's a single
  case-insensitive regex, with `|` between terms. Use `\b` around short words to avoid false
  matches (for example `\bspid\b`).
- **Add a vendor rule:** add a line to `$Rules` above the two generic rules:
  ```powershell
  @{ P='(?i)acmeupdater|acme helper'; F='Updater'; R='Disable'; N='Acme background updater' }
  ```
  `F` is the Flag, `R` the Recommendation (`Disable`, `Review`, `Keep` or `Remove`), and `N` the note shown in the report.
- **Change a default:** edit the `R` value. Or leave the script alone and change the Action in `Findings.csv` each time.

Pull requests with additional ham-radio software patterns are welcome.
