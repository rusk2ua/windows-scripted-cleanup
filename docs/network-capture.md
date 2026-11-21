# Network capture (`ShackCleanup-NetCapture.ps1`)

The capture checks that the cleanup worked on the wire, not just in the registry. It records
every outbound connection for a set time, ties each one to the program or Windows service that
made it, and sorts each destination into one of four verdicts.

| Verdict | Meaning | Examples |
|---|---|---|
| **Should be gone** | Traffic the cleanup was meant to stop | Copilot, News/Bing/Widgets/ads, Office/OneDrive/Teams, activity history |
| **Review** | Not necessarily bad; check the process | Other Microsoft telemetry, Microsoft account sign-in, other Microsoft hosts, third-party programs, connections with no DNS name |
| **Expected** | Traffic you want to keep | Required-level diagnostics (DiagTrack), Windows Update, Defender, Store, certificate checks, time sync, network connectivity check, Edge updates, winget/GitHub |
| **LAN** | Stays on your network (including Tailscale's 100.64.0.0/10) | NAS, rotator, remote rigs |

## Run it

Run it in an admin PowerShell, during a normal session or with the station idle. Four hours is the
default, because several Windows tasks check in only a few times a day.

```powershell
cd C:\ShackCleanup
.\ShackCleanup-NetCapture.ps1
```

Other run lengths:

```powershell
.\ShackCleanup-NetCapture.ps1 -Minutes 60
.\ShackCleanup-NetCapture.ps1 -Minutes 1440
```

Ctrl+C stops it early. It still puts every setting back and reports what it collected.

## How it captures

- **Connection auditing (default):** Windows Filtering Platform auditing (Security log event 5156) records every allowed connection with its process. The script turns it on for the capture, enlarges the Security log to 128 MB if it's smaller, and reads new events every minute.
- **DNS Client log:** records every name looked up, which is how each IP address gets a name.
- **Service names:** connections from `svchost.exe` are labelled with the services running in that process, for example `svchost (DiagTrack)` or `svchost (wuauserv)`.
- **Afterwards:** the auditing setting, the Security log size and the DNS log setting are all restored to exactly what they were. If the old auditing setting can't be read, it's set back to Windows' default, *No Auditing*.
- **`-NoConnectionAudit`:** skips the auditing and samples open TCP connections each minute instead. It's lighter, but it misses brief connections and UDP.

## Output

`C:\ShackCleanup\NetCapture-<timestamp>\`

| File | Contents |
|---|---|
| `Report.html` | Verdict counts, programs that shouldn't be running, then one table per verdict |
| `Summary.csv` | One row per program and destination: verdict, category, ports, count, first and last seen |
| `Connections.csv` | Every outbound connection |
| `DnsQueries.csv` | Every name looked up |
| `Transcript.txt` | Console output |

**Programs that should not be running** lists any of these seen at any point during the capture:
OneDrive, Teams, Widgets, Phone Link, Compatibility Telemetry (`CompatTelRunner`), `DeviceCensus`,
Game Bar, Xbox, Copilot, Clipchamp, and the new Outlook.

## Reading the results

- **Required-level telemetry will show up.** `svchost (DiagTrack)` talking to `v10.events.data.microsoft.com` or similar is the Required diagnostic level you chose to keep. It's listed as Expected.
- **MSN traffic from `msedge`** is Edge's start or new-tab page, so it's Review rather than Should be gone. Set Edge to open a blank page to stop it.
- **Review rows** need a look at *which program* made the connection. A Microsoft host contacted by Windows Update is fine; the same host contacted by something you don't recognize isn't.
- Classification goes by **the name the program looked up**, so traffic to CDNs (Akamai, Azure Front Door) still gets the right category.

## Limits

- **It sees connections, not their contents.** It tells you that DiagTrack sent something, not what.
- **A program that connects by IP address without a DNS lookup** shows up as "No DNS name", with a reverse-DNS name where one exists.
- **Some Windows tasks run daily or weekly.** A 4-hour capture is a good sample, not proof of absence. Run a 24-hour capture after a feature update.
