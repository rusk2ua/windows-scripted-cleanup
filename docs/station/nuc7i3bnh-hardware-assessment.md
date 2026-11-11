# Shack NUC7i3BNH: hardware assessment and upgrade plan

*As of 2026-11-11 · K2UA*

The shack PC (Intel NUC7i3BNH) is serviceable through October 2027. Update the 2017 BIOS now, add RAM, and plan a
replacement within a year. The CPU can't be upgraded, the NVMe SSD is healthy, and Windows 10 is still receiving
security updates via ESU.

## Hardware snapshot

From `Hardware.txt` (ShackCleanup report, 11 Nov 2026).

| Component | Current | Verdict |
| --- | --- | --- |
| Model | Intel NUC7i3BNH (board NUC7i3BNB) | Tall chassis with 2.5" SATA bay |
| CPU | Core i3-7100U, 2 cores / 4 threads, 15 W, Kaby Lake | Soldered; not upgradeable |
| RAM | 2 × 4 GB DDR4-2133 SO-DIMM (8 GB) | Upgrade to 16 or 32 GB |
| Storage | WD Black 256 GB NVMe, 0% wear, 54 °C | Healthy; no action |
| BIOS | BNKBL357.86A.0049, July 2017 | Update to 0093 now |
| TPM | Not detected (PTT off in BIOS) | Enable after BIOS update |
| Secure Boot | Off | Optional to enable |
| OS | Windows 10 Pro 22H2, build 19045.7807 | ESU-enrolled; patched to Oct 2026 |

## CPU

The i3-7100U can't be upgraded: it's soldered to the board, as on every NUC. Two cores and four threads at 15 W
handle one radio on N1MM+ or WSJT-X, but get tight for SO2R with skimmers, a browser and SDR software running
together. More CPU means a replacement mini PC (see [Longer-term plan](#longer-term-plan)).

## RAM

Upgrading to 16 GB is the cheapest worthwhile improvement. Both slots hold 4 GB DDR4-2133 SO-DIMMs, and the board
supports up to 32 GB.

- **16 GB (2 × 8 GB):** the sensible upgrade.
- **32 GB (2 × 16 GB):** if the box stays in service for years.
- Any DDR4 SO-DIMM rated 2400 or 2666 works; the NUC runs it at 2133. Buy a matched pair to keep dual-channel balanced.
- To confirm the need, check Task Manager's Memory tab during normal operating. Sustained use above about 75% means the upgrade will be felt.

## Storage

No action is needed: the WD Black 256 GB NVMe reports healthy, 0% wear, 54 °C. The tall "H" chassis also has a
2.5" SATA bay for extra space without touching the system drive.

## BIOS: update now

The board runs BIOS 0049 (July 2017); the current release is 0093 (25 Dec 2023), 44 versions newer. Intel moved NUC
support to ASUS, which hosts the [BNKBL357 BIOS for the NUC7 BN family](https://www.asus.com/supportonly/nuc7i7bnh/helpdesk_bios),
including the NUC7i3BNH.

- **Security:** the Intel-SA-00086 Management Engine vulnerability is fixed for this model in [version 0057 or later](https://asus.com/uk/support/faq/1052575). The board is still exposed on 0049.
- **Other fixes:** later releases include [processor microcode and security updates](https://archive.org/download/downloadcenter.intel.com/downloadmirror.intel.com_Sept20th2019.tar/downloadmirror.intel.com%2F28990%2Feng%2FBN_0080_ReleaseNotes.pdf).
- **One-way:** after the ME firmware update in 0076, the board can't be downgraded to 0072 or earlier.

Procedure (F7 method, which updates outside Windows):

1. Download the Recovery BIOS update `BN0093.bio` from the ASUS page and copy it to a USB stick.
2. Write down any changed BIOS settings (boot order, power-on after power loss); they may reset to defaults.
3. Plug the NUC into a UPS if possible. Don't interrupt power during the update.
4. With the stick inserted, reboot and press **F7** at the prompt.
5. Select the USB device, select the .BIO file, and confirm. Wait 2–5 minutes for it to finish.
6. Re-apply your settings, then enable PTT (firmware TPM) and, optionally, Secure Boot.

## TPM, Secure Boot and Windows support

The PC is covered by Windows 10 Extended Security Updates through 12 Oct 2027 but can't move to Windows 11.

- **ESU:** the 14 Oct 2026 update (KB5126657) confirms enrollment. Consumer ESU now runs to [12 Oct 2027](https://bleepingcomputer.com/news/microsoft/microsoft-quietly-extends-free-windows-10-esu-support-to-october-2027). Run Windows Update to pick up the November 2026 patches.
- **TPM:** reported as not detected because Intel PTT (firmware TPM 2.0) is off in the BIOS. Turning it on enables BitLocker.
- **Windows 11:** not supported. Microsoft's CPU list starts at 8th-generation Intel; this is 7th-generation.
- **Secure Boot:** off. Worth enabling while in the BIOS, not urgent.

## Longer-term plan

October 2027 is the hard deadline: after it this NUC gets no security patches and has no Windows 11 path.

- [ ] Update BIOS to 0093 (F7 method)
- [ ] Enable PTT; optionally enable Secure Boot
- [ ] Install the November 2026 Windows updates
- [ ] Upgrade RAM to 16 GB (2 × 8 GB DDR4 SO-DIMM)
- [ ] Choose a replacement mini PC with a current Intel or AMD CPU and Windows 11
- [ ] Migrate between contests, using the ShackCleanup report's COM-port and audio-codec list as the checklist
- [ ] Retire the NUC before 12 Oct 2027

## Sources

- [ASUS: NUC7 BN family BIOS & firmware (BNKBL357 v0093)](https://www.asus.com/supportonly/nuc7i7bnh/helpdesk_bios)
- [ASUS: Intel-SA-00086 for NUC](https://asus.com/uk/support/faq/1052575)
- [Intel BIOS release notes, BN 0080 (archived)](https://archive.org/download/downloadcenter.intel.com/downloadmirror.intel.com_Sept20th2019.tar/downloadmirror.intel.com%2F28990%2Feng%2FBN_0080_ReleaseNotes.pdf)
- [BleepingComputer: Windows 10 consumer ESU extended to Oct 2027](https://bleepingcomputer.com/news/microsoft/microsoft-quietly-extends-free-windows-10-esu-support-to-october-2027)
- Hardware data: ShackCleanup report `Hardware.txt`, 11 Nov 2026
