# Windows 11

Since v1.1.0, the scripts detect Windows 11 (build 22000 or later) and add four groups of rows to
`Findings.csv`. Everything from the Windows 10 version still applies: Office 365 / OneDrive / Teams
removal, telemetry at the Required level, startup items, scheduled tasks, services, and winget updates.

| Category | What it covers | Default |
|---|---|---|
| `WindowsApps` | Preinstalled Store apps: Copilot, Clipchamp, News, Weather, Solitaire, Xbox apps, Phone Link, Widgets, Tips and more | Remove |
| `Windows11AI` | Copilot policies, the taskbar Copilot button, Recall, Click to Do | Apply |
| `Windows11UI` | Start, taskbar, Search, File Explorer, Settings, notification and lock-screen ads and nags | Apply |
| `Edge` | Edge startup boost, background running, sidebar/Copilot, shopping, first-run and recommendation nags (Windows 10 too) | Apply |

As always, nothing changes until you run the Act script, and every row can be blanked in the CSV.

## When to run it on a new PC

On a freshly installed PC, run the cleanup **before** you restore any settings or install your station
software. That way everything the report lists is Microsoft's, and nothing of yours can be caught up in it.
With [windows-scripted-pc-migration](https://github.com/rusk2ua/windows-scripted-pc-migration), that's
runbook Phase 1, step 8:

1. Windows Update until nothing's left, including the optional driver updates
2. `03-Build -Apply` from the migration repo, then reboot
3. **This repo:** report, review, `-WhatIf`, then Act; then sign out and back in
4. Drivers, then `04-Apps`, then restore settings

On a new PC, expect a long Office365 / WindowsApps section and a short Startup section.

## Store apps (`WindowsApps`)

**Kept** (never listed): Calculator, Notepad, Paint, Photos, Snipping Tool, Terminal, Camera, Sound
Recorder, Clock, Microsoft Store, App Installer (winget), and all framework and runtime packages (VCLibs,
UI.Xaml, Windows App Runtime, codecs). Removing the Store or App Installer would break winget and some
driver updates.

**Remove by default:**

| Group | Packages |
|---|---|
| AI | Copilot (`Microsoft.Copilot`), Copilot provider, Cortana |
| Content and ads | News, Weather, Bing Search, Widgets (`MicrosoftWindows.Client.WebExperience`), Start feed (`Microsoft.StartExperiencesApp`), Tips, Get Help, Feedback Hub, Maps |
| Apps | Clipchamp, Solitaire, Sticky Notes, Journal, Power Automate, Dev Home, Family Safety, Movies & TV |
| Phone Link and Xbox | Phone Link, cross-device helper, Xbox app, Game Bar, Xbox sign-in, speech overlay and UI components |
| Microsoft account / Office | Microsoft 365 (Office) hub, OneNote, new Outlook, Teams, Skype, Mail & Calendar, To Do, People |

**Review** (your call): Media Player (keep it if you play back audio recordings on this PC), Quick Assist (keep it if someone helps you remotely this way), and Edge Game Assist (Edge reinstalls it during its own updates, so removing it doesn't stick).

Packages are removed for all users and from the provisioning image, so new user accounts don't get them.
A package Windows marks **non-removable** is listed as `Keep` with a note.

The **Copilot app** can be uninstalled like any other app. Windows 11 25H2 also has a
`RemoveMicrosoftCopilotApp` policy (Pro included), but it only acts on PCs that have both Copilot apps
installed and haven't launched Copilot for 28 days, so the script removes the package directly.

The new 25H2 policy "Remove default Microsoft Store packages from the system" is **Enterprise and
Education only**, so on Pro the script removes packages one at a time.

## AI features (`Windows11AI`)

| Setting | Where |
|---|---|
| Copilot off (user and machine policy) | `...\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot = 1` |
| No Copilot taskbar button | `HKCU\...\Explorer\Advanced\ShowCopilotButton = 0` |
| Recall: no snapshots, can't be enabled | `HKLM\...\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1`, `AllowRecallEnablement = 0` |
| Click to Do off | `HKCU\...\Policies\Microsoft\Windows\WindowsAI\DisableClickToDo = 1` |
| Paint: Cocreator, Generative Fill, Image Creator off | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint\DisableCocreator`, `DisableGenerativeFill`, `DisableImageCreator` = 1 |
| Notepad: Copilot writing tools (Rewrite, Summarize, Write) off | `HKLM\SOFTWARE\Policies\WindowsNotepad\DisableAIFeatures = 1` |

Recall and Click to Do only exist on Copilot+ PCs. On other PCs those policies are harmless.

## Shell nags (`Windows11UI`)

| Area | Settings |
|---|---|
| Taskbar | Widgets off (`Dsh\AllowNewsAndInterests = 0`, offered only while the Widgets app is installed), no Chat/Teams icon |
| Start | No tips/app promotions (`Start_IrisRecommendations`), no account notifications, no recently added / most used apps. *Recent files and jump lists* (`Start_TrackDocs`) is **Review**, because turning it off also empties taskbar jump lists. |
| Search | No search highlights, no Bing web results |
| File Explorer | Opens to This PC; Home and Gallery hidden; no OneDrive/sync-provider ads; no Office.com cloud files |
| Settings / notifications | No suggested content in Settings, no tips and suggestions, no post-update "welcome experience", no "finish setting up your device" |
| Lock screen | No fun facts, tips or suggestions |
| Cloud content | No cloud-optimized content, no Microsoft account nags |

Windows may refuse a script's write to the Widgets policy even from an elevated window with full key
permissions (seen on Windows 11 Pro, Nov 2026; likely Windows' User Choice Protection driver). The Act
script logs that as `CHECK`, not `FAILED`. Removing the Widgets app gets rid of Widgets regardless, and
`gpedit.msc` > Windows Components > Widgets > *Allow widgets = Disabled* still sets the policy.

Windows 11 Pro has no supported way to remove Start's *Recommended* section entirely: the
`HideRecommendedSection` policy only works on SE, Education and Enterprise. With these settings applied,
the section stays empty. Start, taskbar and Explorer changes take effect after you sign out and back in.

## Edge (`Edge`)

Edge can't be uninstalled in the US, and other apps use its WebView2 runtime. The scripts keep it
installed and updating, and quiet it with `HKLM\SOFTWARE\Policies\Microsoft\Edge`:

| Policy | Value |
|---|---|
| `StartupBoostEnabled` | 0 |
| `BackgroundModeEnabled` | 0 |
| `HubsSidebarEnabled` (sidebar) | 0 |
| `Microsoft365CopilotChatIconEnabled` (Copilot toolbar button) | 0 |
| `EdgeShoppingAssistantEnabled` | 0 |
| `HideFirstRunExperience` | 1 |
| `ShowRecommendationsEnabled` | 0 |
| `SpotlightExperiencesAndRecommendationsEnabled` | 0 |
| `PersonalizationReportingEnabled` | 0 |
| `DiagnosticData` (required only) | 1 |
| `NewTabPageContentEnabled` (MSN feed) | 0 |
| `EdgeFollowEnabled` | 0 |
| `NewTabPageHideDefaultTopSites` (sponsored and default tiles) | 1 |
| `PromotionalTabsEnabled` | 0 |

Edge will show "Your browser is managed by your organization" afterward. That's expected: it's how Edge
reports that policies are set.

## Local accounts

These scripts don't need a Microsoft account. If you're setting up a new PC: Windows Setup's local-account
workarounds (`OOBE\BYPASSNRO`, `start ms-cxh:localonly` and the "Learn more" link) were all blocked by
October 2026. That leaves install media made with Rufus or an unattend file, or signing in with a
Microsoft account and switching to a local account afterwards in *Settings > Accounts > Your info*.

## Undo

Everything in `Windows11AI`, `Windows11UI` and `Edge` is a registry value, so `ShackCleanup-Undo.ps1`
reverses it. Removed Store apps can be reinstalled from the Microsoft Store.

## Sources

- [Microsoft Windows IT Pro Blog: policy-based removal of preinstalled Store apps (Enterprise/Education)](https://techcommunity.microsoft.com/blog/windows-itpro-blog/policy-based-removal-of-pre-installed-microsoft-store-apps/4463835)
- [Techzine: RemoveMicrosoftCopilotApp on 25H2 with KB5083769, Pro included](https://www.techzine.eu/news/applications/140787/microsoft-offers-it-admins-a-way-to-remove-copilot/)
- [Windows Latest: local-account workarounds blocked (Oct 2026)](https://www.windowslatest.com/2026/10/13/one-click-let-you-escape-microsofts-forced-sign-in-on-windows-11-of-course-microsoft-killed-it/)
- [Pureinfotech: hiding Start's Recommended section](https://pureinfotech.com/remove-start-menu-recommended-items-windows-11)
