# Curat-PC — Windows "do I have a virus?" health check & cleanup (EN/RO)

**One PowerShell script that checks every place real malware hides, gives you a verdict with evidence, cleans junk — and explains the false alarms that make people panic.**

**Un singur script PowerShell care verifică toate locurile unde se ascunde malware real, îți dă un verdict cu probe, curăță fișiere inutile — și explică alarmele false care sperie oamenii.**

> ⚠️ This is **NOT an antivirus** and does not replace Windows Defender. It is a diagnostic and cleanup tool. / Acesta **NU este un antivirus** și nu înlocuiește Windows Defender.

---

## Who this is for / Pentru cine este

You searched something like this and you're scared / Ai căutat ceva de genul acesta și ești speriat:

- *"sfc found corrupt file bthmodem.sys is it a virus"*
- *"Windows Update error 0x800f0923 malware"*
- *"downloaded exe won't run unsigned virus blocking my antivirus"*
- *"driver updater says my PC is at risk"* / *"alerte drivere expirate virus"*
- *"do I have ransomware / crypto virus / miner"* / *"am virus de criptare pe PC"*
- *"hacked pc how to check who logged in"* / *"cum verific dacă am fost spart"*
- *"rogue antivirus fake alerts"* / *"antivirus fals alerte false"*
- *"pc cleaner optimizer scam"* / *"verificare virus pc gratis"*

This tool runs the same checks a professional incident responder would run first, and tells you honestly what it found — including when the answer is **"nothing, and here's why what you saw was harmless."**

## Quick start / Pornire rapidă

1. Download `Curat-PC.ps1` and `Curat-PC.cmd` into the same folder.
2. Double-click **`Curat-PC.cmd`** (it asks for Administrator).
3. Read the HTML report that opens (saved on your Desktop).

```powershell
.\Curat-PC.ps1            # scan only — changes NOTHING / doar scanare
.\Curat-PC.ps1 -Fix       # + safe cleanup (temp, proxy reset, disable Guest)
.\Curat-PC.ps1 -Deep      # + slow integrity checks (DISM, SFC, Defender scan)
.\Curat-PC.ps1 -Deep -Fix # everything / totul
.\Curat-PC.ps1 -Json      # + machine-readable JSON report / + raport JSON
```

Works on Windows 10 and 11 with built-in PowerShell 5.1. No dependencies, no internet access needed, nothing uploaded anywhere.

## What it checks / Ce verifică

| Area | Checks |
|---|---|
| **Persistence** | Run/RunOnce keys, Startup folders (flags script files), Winlogon Shell/Userinit, AppInit_DLLs, IFEO debugger hijacks, WMI event subscriptions, non-Microsoft scheduled tasks, unquoted service paths |
| **Defender tampering** | Tamper Protection, real-time protection, hidden exclusions, threat history |
| **Ransomware** | Shadow copies & restore points intact, ransom notes, encrypted-file extensions |
| **Cryptominer** | CPU load (averaged over multiple samples), mining-pool connections, full remote-port inventory |
| **Access** | Guest account, admins, UAC disabled, RDP/WinRM, failed & remote logons (7 days), cleared logs |
| **Network** | WinHTTP/browser proxy hijack, PAC URL, hosts file, firewall, DNS servers, SMBv1 |
| **Code trust** | Authenticode signatures of all running processes and kernel drivers, machine-wide execution policy |
| **Bundleware** | Aggressive "driver updater / PC optimizer" apps that show fake scary alerts |
| **Broken downloads** | Detects truncated .exe files that "won't run" (the #1 fake virus symptom) |

## What `-Fix` does (and never does) / Ce face `-Fix` (și ce nu face niciodată)

Does: disable Guest account, reset proxy, flush DNS, clean temp folders and Windows Update cache, optional hosts-file cleanup with per-line confirmation.

**Never does:** uninstall software, delete your files, kill processes, or touch drivers. Potentially unwanted programs are *reported* with their uninstall commands — removing them is your decision.

## The false alarms it explains / Alarmele false pe care le explică

1. **SFC says `bthmodem.sys` is corrupt** — known false positive on Windows 11 22621.
2. **Windows Update `0x800f0923`** — means "you're in Safe Mode", not "you're infected".
3. **Store apps look unsigned** — MSIX apps are signed per-package, not per-file.
4. **A downloaded .exe won't run and "has no signature"** — if its size is an exact number of MB, the download was cut off; the signature lives at the end of the file. Re-download it.
5. **Ports 135/445/49664+ are "open"** — standard Windows RPC on every PC.
6. **"Your drivers put your PC at risk!" popups** — a paid optimizer app doing marketing, not malware.

## If it DOES find something real / Dacă găsește ceva real

The report tells you: disconnect the network, run **Microsoft Defender Offline scan**, change passwords from another device, and for ransomware check [nomoreransom.org](https://www.nomoreransom.org) before even thinking about paying.

## License

MIT — use it, share it, translate it.

---

*Keywords: windows virus check script, powershell malware audit, fake antivirus alerts, rogue antivirus, ransomware check tool, cryptominer detection, pc health check, verificare virus pc, curatare pc, script verificare malware, calculator infectat, alerte false antivirus, 0x800f0923, bthmodem.sys, sfc scannow corrupt file, exe not running unsigned, driver updater scam*
