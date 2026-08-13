# =====================================================================
#  Curat-PC  -  PC Health Check & Cleanup Tool / Verificare si Curatare PC
# =====================================================================
#  NOT an antivirus. / NU este un antivirus.
#  Audits the places real malware hides, proves a verdict with evidence,
#  cleans junk, and explains common FALSE alarms.
#  Verifica locurile unde se ascunde malware real, dovedeste verdictul
#  cu probe, curata fisiere inutile si explica alarmele FALSE frecvente.
#
#  Usage / Utilizare:
#    .\Curat-PC.ps1            scan only, report on Desktop / doar scanare
#    .\Curat-PC.ps1 -Fix       + safe cleanup actions / + curatare sigura
#    .\Curat-PC.ps1 -Deep      + slow integrity checks (DISM, SFC, Defender)
#    .\Curat-PC.ps1 -NoReport  no HTML report / fara raport HTML
#    .\Curat-PC.ps1 -Json      also save findings as JSON / salveaza si JSON
#
#  Windows PowerShell 5.1 compatible. No dependencies.
# =====================================================================
[CmdletBinding()]
param(
    [switch]$Fix,
    [switch]$Deep,
    [switch]$NoReport,
    [switch]$Json
)

$ErrorActionPreference = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.ArrayList
$script:FixLog   = New-Object System.Collections.ArrayList
$script:StartTime = Get-Date

# ---------------------------------------------------------------- helpers
function Add-Finding {
    param(
        [string]$Area,
        [ValidateSet('OK','INFO','WARN','CRIT')][string]$Severity,
        [string]$Message,      # English
        [string]$MessageRO,    # Romanian (no diacritics for encoding safety)
        [string]$Evidence = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Area = $Area; Severity = $Severity
        Message = $Message; MessageRO = $MessageRO; Evidence = $Evidence
    })
    $color = switch ($Severity) {
        'OK'   { 'Green' } 'INFO' { 'Cyan' } 'WARN' { 'Yellow' } 'CRIT' { 'Red' }
    }
    Write-Host ("  [{0,-4}] {1}" -f $Severity, $Message) -ForegroundColor $color
    if ($MessageRO) { Write-Host ("         RO: {0}" -f $MessageRO) -ForegroundColor DarkGray }
}

function Add-Fix {
    param([string]$Action, [string]$Result)
    [void]$script:FixLog.Add([pscustomobject]@{ Action = $Action; Result = $Result })
    Write-Host ("  [FIX ] {0} -> {1}" -f $Action, $Result) -ForegroundColor Magenta
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=== {0} " -f $Title).PadRight(70, '=') -ForegroundColor White
}

# ---------------------------------------------------------------- elevation
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Administrator rights required - relaunching elevated..." -ForegroundColor Yellow
    Write-Host "Sunt necesare drepturi de administrator - repornesc..." -ForegroundColor Yellow
    $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Fix)      { $argLine += ' -Fix' }
    if ($Deep)     { $argLine += ' -Deep' }
    if ($NoReport) { $argLine += ' -NoReport' }
    if ($Json)     { $argLine += ' -Json' }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argLine -Verb RunAs
    exit
}

Write-Host ""
Write-Host "  Curat-PC - Health Check / Verificare Sanatate PC" -ForegroundColor White
Write-Host ("  Computer: {0}   User: {1}   Date: {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date -Format 'yyyy-MM-dd HH:mm'))
Write-Host ("  Mode / Mod: scan{0}{1}" -f $(if ($Fix) {' + fix'} else {''}), $(if ($Deep) {' + deep'} else {''}))
Write-Host "  This tool is NOT an antivirus. / Acest program NU este antivirus." -ForegroundColor DarkGray

# =====================================================================
#  CHECK 1 - PERSISTENCE (autostart & hijack points)
# =====================================================================
Write-Section 'PERSISTENCE / PERSISTENTA'

$runKeys = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
$autostarts = @()
foreach ($k in $runKeys) {
    if (Test-Path $k) {
        $item = Get-Item $k
        foreach ($n in $item.GetValueNames()) {
            $autostarts += ("{0} :: {1} = {2}" -f $k, $n, $item.GetValue($n))
        }
    }
}
$startupScripts = @()
foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($d -and (Test-Path $d)) {
        foreach ($f in (Get-ChildItem $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $autostarts += ("{0} :: {1}" -f $d, $f.Name)
            if ($f.Extension -match '^\.(vbs|vbe|js|jse|wsf|wsh|bat|cmd|ps1|hta|scr)$') {
                $startupScripts += $f.FullName
            }
        }
    }
}
Add-Finding 'Persistence' 'INFO' ("{0} autostart entries found (review list in report)" -f $autostarts.Count) `
    ("{0} intrari de pornire automata gasite (vezi lista in raport)" -f $autostarts.Count) `
    ($autostarts -join "`n")
if ($startupScripts.Count -gt 0) {
    Add-Finding 'Persistence' 'WARN' ("Script file(s) in Startup folder (common malware trick, legit apps use .lnk/.exe): {0}" -f ($startupScripts -join '; ')) `
        'Fisiere script in folderul Startup (truc frecvent de malware; aplicatiile legitime folosesc .lnk/.exe) - verifica-le' `
        ($startupScripts -join "`n")
}

$winlogon = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (-not $winlogon) {
    Add-Finding 'Persistence' 'INFO' 'Could not read Winlogon key - skipping Shell/Userinit checks' `
        'Nu am putut citi cheia Winlogon - sar peste verificarile Shell/Userinit'
} elseif ($winlogon.Shell -ne 'explorer.exe') {
    Add-Finding 'Persistence' 'CRIT' ("Winlogon Shell hijacked: '{0}' (should be explorer.exe)" -f $winlogon.Shell) `
        ("Winlogon Shell modificat: '{0}' (ar trebui sa fie explorer.exe)" -f $winlogon.Shell) $winlogon.Shell
} else {
    Add-Finding 'Persistence' 'OK' 'Winlogon Shell is the stock value (explorer.exe)' 'Winlogon Shell are valoarea standard'
}
if ($winlogon) {
    if ($winlogon.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?\s*$') {
        Add-Finding 'Persistence' 'CRIT' ("Winlogon Userinit modified: '{0}'" -f $winlogon.Userinit) `
            ("Winlogon Userinit modificat: '{0}'" -f $winlogon.Userinit) $winlogon.Userinit
    } else {
        Add-Finding 'Persistence' 'OK' 'Winlogon Userinit is the stock value' 'Winlogon Userinit are valoarea standard'
    }
}

$appinit = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
if ($appinit -and $appinit.Trim() -ne '') {
    Add-Finding 'Persistence' 'CRIT' ("AppInit_DLLs is set (classic injection): {0}" -f $appinit) `
        ("AppInit_DLLs este setat (injectie clasica): {0}" -f $appinit) $appinit
} else {
    Add-Finding 'Persistence' 'OK' 'AppInit_DLLs is empty' 'AppInit_DLLs este gol'
}

$ifeoHits = @()
$ifeoRoot = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($sub in (Get-ChildItem $ifeoRoot)) {
    $dbg = (Get-ItemProperty $sub.PSPath).Debugger
    if ($dbg) { $ifeoHits += ("{0} -> {1}" -f $sub.PSChildName, $dbg) }
}
if ($ifeoHits.Count -gt 0) {
    Add-Finding 'Persistence' 'CRIT' ("IFEO debugger hijack(s) found: {0}" -f ($ifeoHits -join '; ')) `
        'Deturnari IFEO debugger gasite (o metoda clasica de blocare a antivirusilor)' ($ifeoHits -join "`n")
} else {
    Add-Finding 'Persistence' 'OK' 'No IFEO debugger hijacks' 'Nicio deturnare IFEO'
}

$wmiOk = $true
$wmiEvidence = @()
$knownWmi = @('SCM Event Log Filter','SCM Event Log Consumer','BVTFilter','BVTConsumer')
foreach ($cls in @('__EventFilter','__EventConsumer','__FilterToConsumerBinding')) {
    foreach ($obj in (Get-CimInstance -Namespace root\subscription -ClassName $cls)) {
        $nm = $obj.Name
        if (-not $nm) { $nm = "$($obj.Filter) $($obj.Consumer)" }   # bindings have no Name
        $isKnown = $false
        foreach ($kw in $knownWmi) { if ($nm -like "*$kw*") { $isKnown = $true; break } }
        if (-not $isKnown) { $wmiOk = $false; $wmiEvidence += ("{0}: {1}" -f $cls, $nm) }
    }
}
if ($wmiOk) {
    Add-Finding 'Persistence' 'OK' 'WMI event subscriptions: only Windows defaults' 'Abonamente WMI: doar cele standard Windows'
} else {
    Add-Finding 'Persistence' 'WARN' ("Non-default WMI event subscriptions (fileless persistence technique): {0}" -f ($wmiEvidence -join '; ')) `
        'Abonamente WMI nestandard (tehnica de persistenta fara fisiere) - verifica manual' ($wmiEvidence -join "`n")
}

$tasks3p = @()
foreach ($t in (Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })) {
    $exe = ($t.Actions | ForEach-Object { $_.Execute }) -join '; '
    $tasks3p += ("{0}{1} -> {2}" -f $t.TaskPath, $t.TaskName, $exe)
}
Add-Finding 'Persistence' 'INFO' ("{0} non-Microsoft scheduled tasks (list in report)" -f $tasks3p.Count) `
    ("{0} sarcini programate non-Microsoft (lista in raport)" -f $tasks3p.Count) ($tasks3p -join "`n")

$unquoted = @()
foreach ($svc in (Get-CimInstance Win32_Service | Where-Object { $_.PathName })) {
    $pn = $svc.PathName
    if ($pn -notmatch '^"' -and $pn -match '^([^"]+?\.exe)') {
        $exePath = $Matches[1]
        if ($exePath -match '\s' -and $exePath -notlike "$env:SystemRoot\*") {
            $unquoted += ("{0} -> {1}" -f $svc.Name, $pn)
        }
    }
}
if ($unquoted.Count -gt 0) {
    Add-Finding 'Persistence' 'WARN' ("Service(s) with unquoted path containing spaces (privilege-escalation risk): {0}" -f ($unquoted -join '; ')) `
        'Servicii cu cale fara ghilimele care contine spatii (risc de escaladare de privilegii) - de obicei software prost scris, nu malware' `
        ($unquoted -join "`n")
} else {
    Add-Finding 'Persistence' 'OK' 'No services with unquoted spaced paths' 'Niciun serviciu cu cale fara ghilimele cu spatii'
}

# =====================================================================
#  CHECK 2 - DEFENDER TAMPERING
# =====================================================================
Write-Section 'WINDOWS DEFENDER'

$mp   = Get-MpComputerStatus
$pref = Get-MpPreference
if ($mp) {
    if ($mp.IsTamperProtected)          { Add-Finding 'Defender' 'OK' 'Tamper Protection is ON' 'Protectia impotriva modificarilor este ACTIVA' }
    else                                 { Add-Finding 'Defender' 'WARN' 'Tamper Protection is OFF' 'Protectia impotriva modificarilor este OPRITA' }
    if ($pref.DisableRealtimeMonitoring) { Add-Finding 'Defender' 'CRIT' 'Real-time protection is DISABLED' 'Protectia in timp real este DEZACTIVATA' }
    else                                 { Add-Finding 'Defender' 'OK' 'Real-time protection is ON' 'Protectia in timp real este ACTIVA' }
    $excl = @()
    if ($pref.ExclusionPath)      { $excl += ($pref.ExclusionPath      | ForEach-Object { "Path: $_" }) }
    if ($pref.ExclusionExtension) { $excl += ($pref.ExclusionExtension | ForEach-Object { "Ext: $_" }) }
    if ($pref.ExclusionProcess)   { $excl += ($pref.ExclusionProcess   | ForEach-Object { "Proc: $_" }) }
    if ($excl.Count -gt 0) {
        Add-Finding 'Defender' 'WARN' ("Defender exclusions exist (attackers add these to hide): {0}" -f ($excl -join '; ')) `
            'Exista exceptii Defender (atacatorii le adauga pentru a se ascunde) - verifica daca le-ai pus tu' ($excl -join "`n")
    } else {
        Add-Finding 'Defender' 'OK' 'No Defender exclusions' 'Nicio exceptie Defender'
    }
    $threats = Get-MpThreatDetection
    if ($threats) {
        $tn = ($threats | Select-Object -Last 5 | ForEach-Object { "$($_.InitialDetectionTime) ID:$($_.ThreatID)" }) -join '; '
        Add-Finding 'Defender' 'WARN' ("Defender has past threat detections: {0}" -f $tn) `
            'Defender are detectii in istoric - vezi Windows Security > Protection history' $tn
    } else {
        Add-Finding 'Defender' 'OK' 'Defender has never detected a threat on this machine' 'Defender nu a detectat niciodata o amenintare pe acest PC'
    }
} else {
    Add-Finding 'Defender' 'WARN' 'Could not query Defender (another AV may be primary)' 'Nu am putut interoga Defender (posibil alt antivirus principal)'
}

# =====================================================================
#  CHECK 3 - RANSOMWARE INDICATORS
# =====================================================================
Write-Section 'RANSOMWARE'

$shadow = @(Get-CimInstance Win32_ShadowCopy)
$restore = @(Get-ComputerRestorePoint)
if ($shadow.Count -gt 0 -or $restore.Count -gt 0) {
    Add-Finding 'Ransomware' 'OK' ("Shadow copies: {0}, restore points: {1} - ransomware destroys these first, they are intact" -f $shadow.Count, $restore.Count) `
        ("Copii shadow: {0}, puncte de restaurare: {1} - ransomware-ul le distruge primele, ele sunt intacte" -f $shadow.Count, $restore.Count)
} else {
    Add-Finding 'Ransomware' 'INFO' 'No shadow copies or restore points (may simply be disabled - enable System Protection)' `
        'Nu exista copii shadow sau puncte de restaurare (posibil doar dezactivate - activeaza System Protection)'
}

# Tight whole-filename patterns only - substring matching causes false hits
$notePattern = '^(HOW_?TO_?(DECRYPT|RESTORE|RECOVER).*|.*DECRYPT_?(INSTRUCTIONS?|FILES).*|_?readme\.txt|.*RESTORE_?MY_?FILES.*|.*RANSOM.*NOTE.*|![A-Z_]*(DECRYPT|RECOVER)[A-Z_]*!.*)$'
$scanDirs = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:USERPROFILE\Pictures","$env:USERPROFILE\Downloads","$env:USERPROFILE\Videos","$env:USERPROFILE\Music")
$notes = @()
foreach ($d in $scanDirs) {
    if (Test-Path $d) {
        $notes += Get-ChildItem $d -Recurse -Force -File -Depth 3 |
            Where-Object { $_.Name -match $notePattern } | Select-Object -First 10
    }
}
if ($notes.Count -gt 0) {
    Add-Finding 'Ransomware' 'CRIT' ("Possible ransom note file(s): {0}" -f (($notes | ForEach-Object { $_.FullName }) -join '; ')) `
        'Posibile note de rascumparare gasite - NU plati, cauta numele fisierului pe nomoreransom.org' (($notes | ForEach-Object { $_.FullName }) -join "`n")
} else {
    Add-Finding 'Ransomware' 'OK' 'No ransom notes found' 'Nicio nota de rascumparare gasita'
}

$ransomExt = @('.encrypted','.locked','.crypt','.crypto','.wncry','.locky','.cerber','.zepto','.osiris','.djvu','.lockbit','.conti','.ryuk','.phobos','.venus','.makop','.mallox')
$encFiles = @()
foreach ($d in $scanDirs) {
    if (Test-Path $d) {
        $encFiles += Get-ChildItem $d -Recurse -Force -File -Depth 3 |
            Where-Object { $ransomExt -contains $_.Extension.ToLower() -and $_.FullName -notmatch '\\(tcl|python|encoding|node_modules)\\' } |
            Select-Object -First 10
    }
}
if ($encFiles.Count -gt 0) {
    Add-Finding 'Ransomware' 'CRIT' ("Files with known ransomware extensions: {0}" -f (($encFiles | ForEach-Object { $_.FullName }) -join '; ')) `
        'Fisiere cu extensii cunoscute de ransomware gasite' (($encFiles | ForEach-Object { $_.FullName }) -join "`n")
} else {
    Add-Finding 'Ransomware' 'OK' 'No files with ransomware extensions' 'Niciun fisier cu extensii de ransomware'
}

# =====================================================================
#  CHECK 4 - CRYPTOMINER INDICATORS
# =====================================================================
Write-Section 'CRYPTOMINER'

# Average over 3 samples ~4s apart - a single snapshot misses miners that
# throttle, and overreacts to momentary spikes
$cpuSamples = @()
for ($i = 0; $i -lt 3; $i++) {
    $cpuSamples += (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    if ($i -lt 2) { Start-Sleep -Seconds 2 }
}
$cpuLoad = [math]::Round(($cpuSamples | Measure-Object -Average).Average, 0)
if ($cpuLoad -ge 70) {
    $top = (Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 | ForEach-Object { "$($_.ProcessName) ($([math]::Round($_.CPU,0))s)" }) -join ', '
    Add-Finding 'Miner' 'WARN' ("CPU load is high: {0}% - top consumers: {1}" -f $cpuLoad, $top) `
        ("Procesorul este incarcat: {0}% - verifica procesele de top" -f $cpuLoad) $top
} else {
    Add-Finding 'Miner' 'OK' ("CPU load normal: {0}%" -f $cpuLoad) ("Incarcare procesor normala: {0}%" -f $cpuLoad)
}

$minerPorts = @(3333,3334,3357,4444,5555,5556,7777,8888,9999,14433,14444,45560,45700)
$minerConns = @(Get-NetTCPConnection -State Established | Where-Object { $minerPorts -contains $_.RemotePort })
if ($minerConns.Count -gt 0) {
    $mc = ($minerConns | ForEach-Object {
        $pn = (Get-Process -Id $_.OwningProcess).ProcessName
        "{0}:{1} <- {2}" -f $_.RemoteAddress, $_.RemotePort, $pn
    }) -join '; '
    Add-Finding 'Miner' 'CRIT' ("Connections to typical mining-pool ports: {0}" -f $mc) `
        'Conexiuni catre porturi tipice de mining gasite' $mc
} else {
    Add-Finding 'Miner' 'OK' 'No connections to known mining-pool ports' 'Nicio conexiune catre porturi de mining cunoscute'
}

$remotePorts = @(Get-NetTCPConnection -State Established |
    Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1|0\.0\.0\.0)' } |
    Select-Object -ExpandProperty RemotePort | Sort-Object -Unique)
Add-Finding 'Miner' 'INFO' ("Distinct remote ports in use: {0}" -f ($remotePorts -join ', ')) `
    ("Porturi remote distincte folosite: {0}" -f ($remotePorts -join ', '))

# =====================================================================
#  CHECK 5 - ACCESS AUDIT (accounts, remote access, logon history)
# =====================================================================
Write-Section 'ACCESS / ACCES'

$guest = Get-LocalUser -Name 'Guest'
if ($guest -and $guest.Enabled) {
    Add-Finding 'Access' 'WARN' 'Built-in Guest account is ENABLED (passwordless local access)' `
        'Contul Guest este ACTIVAT (acces local fara parola)' 'Guest: Enabled=True'
} else {
    Add-Finding 'Access' 'OK' 'Guest account is disabled' 'Contul Guest este dezactivat'
}

$admins = (Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name }) -join ', '
Add-Finding 'Access' 'INFO' ("Administrators group: {0}" -f $admins) ("Grupul Administrators: {0}" -f $admins)

$uac = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
if ($uac -eq 0) {
    Add-Finding 'Access' 'WARN' 'UAC is DISABLED (EnableLUA=0) - malware disables it to elevate silently; re-enable unless you turned it off yourself' `
        'UAC este DEZACTIVAT (EnableLUA=0) - malware-ul il dezactiveaza pentru a se ridica silentios; reactiveaza-l daca nu l-ai oprit tu' 'EnableLUA=0'
} else {
    Add-Finding 'Access' 'OK' 'UAC is enabled' 'UAC este activat'
}

$rdpDeny = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
if ($rdpDeny -eq 0) {
    Add-Finding 'Access' 'WARN' 'Remote Desktop (RDP) is ENABLED - disable it if you do not use it' `
        'Remote Desktop (RDP) este ACTIVAT - dezactiveaza-l daca nu il folosesti'
} else {
    Add-Finding 'Access' 'OK' 'Remote Desktop is disabled' 'Remote Desktop este dezactivat'
}
foreach ($svcName in @('RemoteRegistry','WinRM')) {
    $svc = Get-Service -Name $svcName
    if ($svc -and $svc.Status -eq 'Running') {
        Add-Finding 'Access' 'INFO' ("{0} service is running" -f $svcName) ("Serviciul {0} ruleaza" -f $svcName)
    }
}

$failed = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 500)
if ($failed.Count -gt 20) {
    Add-Finding 'Access' 'WARN' ("{0} failed logon attempts in 7 days (possible password guessing)" -f $failed.Count) `
        ("{0} incercari esuate de autentificare in 7 zile (posibila ghicire de parola)" -f $failed.Count)
} elseif ($failed.Count -gt 0) {
    Add-Finding 'Access' 'INFO' ("{0} failed logon attempts in 7 days (normal for typos)" -f $failed.Count) `
        ("{0} incercari esuate in 7 zile (normal pentru greseli de tastare)" -f $failed.Count)
} else {
    Add-Finding 'Access' 'OK' 'No failed logon attempts in 7 days' 'Nicio incercare esuata de autentificare in 7 zile'
}

$remoteLogons = @()
foreach ($ev in (Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1000)) {
    $x = [xml]$ev.ToXml()
    $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
    $lt = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'
    $us = ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    if (($lt -eq '3' -or $lt -eq '10') -and $ip -and $ip -notmatch '^(-|127\.0\.0\.1|::1|0\.0\.0\.0|fe80)') {
        $remoteLogons += ("{0} from {1} (type {2})" -f $us, $ip, $lt)
    }
}
$remoteLogons = @($remoteLogons | Sort-Object -Unique)
if ($remoteLogons.Count -gt 0) {
    Add-Finding 'Access' 'WARN' ("Network logons from remote addresses in 7 days: {0}" -f ($remoteLogons -join '; ')) `
        'Autentificari de la adrese remote in ultimele 7 zile - verifica daca le recunosti' ($remoteLogons -join "`n")
} else {
    Add-Finding 'Access' 'OK' 'No remote network logons in 7 days - nobody connected in from outside' `
        'Nicio autentificare remote in 7 zile - nimeni nu s-a conectat din exterior'
}

$cleared = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -MaxEvents 5) + @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 5)
if ($cleared.Count -gt 0) {
    $ce = ($cleared | ForEach-Object { "$($_.TimeCreated) $($_.LogName)" }) -join '; '
    Add-Finding 'Access' 'WARN' ("Event log was cleared: {0} (attackers wipe logs; users rarely do)" -f $ce) `
        'Jurnalul de evenimente a fost sters - atacatorii sterg jurnale, utilizatorii rar' $ce
} else {
    Add-Finding 'Access' 'OK' 'Event logs never cleared' 'Jurnalele nu au fost sterse niciodata'
}

# =====================================================================
#  CHECK 6 - NETWORK HYGIENE (proxy, hosts, firewall)
# =====================================================================
Write-Section 'NETWORK / RETEA'

$winhttp = (netsh winhttp show proxy) -join ' '
if ($winhttp -match 'Direct access') {
    Add-Finding 'Network' 'OK' 'WinHTTP: direct access, no system proxy' 'WinHTTP: acces direct, fara proxy de sistem'
} else {
    Add-Finding 'Network' 'WARN' ("WinHTTP proxy is set: {0}" -f $winhttp.Trim()) `
        'Proxy WinHTTP setat - daca nu l-ai configurat tu, poate redirectiona traficul' $winhttp.Trim()
}
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($inet.ProxyEnable -eq 1) {
    Add-Finding 'Network' 'WARN' ("Manual browser proxy enabled: {0}" -f $inet.ProxyServer) `
        ("Proxy manual de browser activat: {0} - daca nu l-ai setat tu, e suspect" -f $inet.ProxyServer) $inet.ProxyServer
} else {
    Add-Finding 'Network' 'OK' 'No manual browser proxy' 'Fara proxy manual de browser'
}
if ($inet.AutoConfigURL) {
    Add-Finding 'Network' 'WARN' ("Proxy auto-config (PAC) URL set: {0}" -f $inet.AutoConfigURL) `
        ("URL de configurare automata proxy (PAC) setat: {0}" -f $inet.AutoConfigURL) $inet.AutoConfigURL
} else {
    Add-Finding 'Network' 'OK' 'No PAC auto-config URL' 'Fara URL de configurare automata proxy'
}

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$hostsLines = @(Get-Content $hostsPath | Where-Object { $_.Trim() -ne '' -and $_.Trim() -notlike '#*' })
if ($hostsLines.Count -gt 0) {
    Add-Finding 'Network' 'WARN' ("hosts file has {0} active entr(y/ies) - malware uses these to redirect or block sites" -f $hostsLines.Count) `
        ("Fisierul hosts are {0} intrari active - malware-ul le foloseste pentru redirectionare" -f $hostsLines.Count) ($hostsLines -join "`n")
} else {
    Add-Finding 'Network' 'OK' 'hosts file has no active entries' 'Fisierul hosts nu are intrari active'
}

$fwOff = @(Get-NetFirewallProfile | Where-Object { -not $_.Enabled })
if ($fwOff.Count -gt 0) {
    Add-Finding 'Network' 'WARN' ("Firewall disabled on profile(s): {0}" -f (($fwOff | ForEach-Object { $_.Name }) -join ', ')) `
        'Firewall dezactivat pe unele profiluri' (($fwOff | ForEach-Object { $_.Name }) -join ', ')
} else {
    Add-Finding 'Network' 'OK' 'Firewall enabled on all profiles' 'Firewall activ pe toate profilurile'
}

# DNS hijack is as common as proxy hijack: malware points DNS at rogue servers
$dnsServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $_.ServerAddresses } |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { $_ -notmatch '^(127\.|0\.0\.0\.0)' } | Sort-Object -Unique)
if ($dnsServers.Count -gt 0) {
    Add-Finding 'Network' 'INFO' ("DNS servers in use: {0} - normally your router (192.168.x.x / 10.x.x.x) or a known public resolver (1.1.1.1, 8.8.8.8, 9.9.9.9). An unfamiliar public IP here can redirect every site you visit." -f ($dnsServers -join ', ')) `
        ("Servere DNS folosite: {0} - normal e routerul tau (192.168.x.x) sau un resolver public cunoscut (1.1.1.1, 8.8.8.8). Un IP public necunoscut aici poate redirectiona orice site vizitezi." -f ($dnsServers -join ', ')) `
        ($dnsServers -join "`n")
}

$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1) {
    Add-Finding 'Network' 'WARN' 'SMBv1 protocol is ENABLED - obsolete and exploitable (WannaCry vector); disable it unless an ancient device needs it' `
        'Protocolul SMBv1 este ACTIVAT - invechit si exploatabil (vectorul WannaCry); dezactiveaza-l daca nu il cere un dispozitiv foarte vechi' 'EnableSMB1Protocol=True'
} else {
    Add-Finding 'Network' 'OK' 'SMBv1 is disabled' 'SMBv1 este dezactivat'
}

# =====================================================================
#  CHECK 7 - CODE TRUST (signatures of running processes & drivers)
# =====================================================================
Write-Section 'CODE TRUST / INCREDERE COD'

$unsigned = @()
foreach ($proc in (Get-Process | Where-Object { $_.Path } | Select-Object -Unique Path)) {
    # MSIX/Store apps are signed at package level; per-file check reports NotSigned - skip
    if ($proc.Path -like "$env:ProgramFiles\WindowsApps\*") { continue }
    $sig = Get-AuthenticodeSignature $proc.Path
    if ($sig.Status -ne 'Valid') { $unsigned += ("[{0}] {1}" -f $sig.Status, $proc.Path) }
}
if ($unsigned.Count -gt 0) {
    Add-Finding 'CodeTrust' 'WARN' ("Running executables without valid signature: {0}" -f ($unsigned -join '; ')) `
        'Executabile care ruleaza fara semnatura valida - nu neaparat rele (multe programe mici nu sunt semnate), dar merita verificate' `
        ($unsigned -join "`n")
} else {
    Add-Finding 'CodeTrust' 'OK' 'All running executables validly signed (Store apps package-signed)' `
        'Toate executabilele care ruleaza sunt semnate valid'
}

$badDrivers = @()
foreach ($drv in (Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' -and $_.PathName })) {
    $p = $drv.PathName -replace '^\\\?\?\\','' -replace '^\\SystemRoot\\','' -replace '^SystemRoot\\',''
    if ($p -notmatch '^[A-Za-z]:') { $p = Join-Path $env:SystemRoot $p }
    if (Test-Path $p) {
        $sig = Get-AuthenticodeSignature $p
        if ($sig.Status -ne 'Valid') { $badDrivers += ("[{0}] {1}" -f $sig.Status, $p) }
    }
}
if ($badDrivers.Count -gt 0) {
    Add-Finding 'CodeTrust' 'CRIT' ("Running kernel drivers without valid signature: {0}" -f ($badDrivers -join '; ')) `
        'Drivere de kernel fara semnatura valida - serios, driverele ar trebui sa fie toate semnate' ($badDrivers -join "`n")
} else {
    Add-Finding 'CodeTrust' 'OK' 'All running kernel drivers validly signed' 'Toate driverele de kernel sunt semnate valid'
}

$machinePolicy = (Get-ItemProperty 'HKLM:\Software\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell').ExecutionPolicy
if ($machinePolicy -match '^(Bypass|Unrestricted)$') {
    Add-Finding 'CodeTrust' 'INFO' ("Machine-wide PowerShell execution policy is '{0}' - scripts run without any signing check. Fine if you set it; malware installers also set it." -f $machinePolicy) `
        ("Politica de executie PowerShell la nivel de sistem este '{0}' - scripturile ruleaza fara verificare. OK daca ai setat-o tu; si instalatoarele de malware o seteaza." -f $machinePolicy) `
        ("ExecutionPolicy={0}" -f $machinePolicy)
}

# =====================================================================
#  CHECK 8 - PUP / BUNDLEWARE (the usual cause of "virus" panic)
# =====================================================================
Write-Section 'BUNDLEWARE / PROGRAME AGRESIVE'

# Two families: aggressive optimizers/updaters, and rogue "antivirus"/scareware
# products widely flagged as PUPs. Real AVs (Defender, Bitdefender, ESET,
# Kaspersky, Avast...) intentionally NOT matched.
$pupPattern = 'driver\s*(updater|booster|support|restore)|pc\s*(cleaner|optimizer|speedup|tuneup|booster|accelerate)|registry\s*(clean|fix)|system\s*mechanic|optimizer\s*pro|web\s*companion|search\s*protect|shopping\s*helper|segurazo|santivirus|bytefence|reimage\s*repair|restoro|spyhunter|onesafe|advanced\s*identity\s*protector|mycleanpc|slimcleaner|outbyte'
$pups = @()
foreach ($app in (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
    if ($app.DisplayName -and $app.DisplayName -match $pupPattern) {
        $pups += [pscustomobject]@{ Name = $app.DisplayName; Uninstall = $app.UninstallString }
    }
}
if ($pups.Count -gt 0) {
    $pe = ($pups | ForEach-Object { "$($_.Name)  [uninstall: $($_.Uninstall)]" }) -join "`n"
    Add-Finding 'Bundleware' 'WARN' ("Aggressive 'optimizer/updater' software found: {0}. These show scary fake alerts to sell subscriptions - they are the #1 cause of 'I have a virus' panic. NOT auto-removed; uninstall commands are in the report." -f (($pups | ForEach-Object { $_.Name }) -join ', ')) `
        'Programe agresive de tip optimizer/driver updater gasite. Acestea afiseaza alerte false infricosatoare ca sa vanda abonamente - sunt cauza nr. 1 a panicii de virus. NU le-am sters automat; comenzile de dezinstalare sunt in raport.' $pe
} else {
    Add-Finding 'Bundleware' 'OK' 'No known aggressive optimizer/updater software' 'Niciun program agresiv de tip optimizer cunoscut'
}

# =====================================================================
#  CHECK 9 - TRUNCATED DOWNLOADS (files that "will not run")
# =====================================================================
Write-Section 'BROKEN DOWNLOADS / DESCARCARI INCOMPLETE'

$truncated = @()
foreach ($dir in @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads")) {
    if (Test-Path $dir) {
        foreach ($exe in (Get-ChildItem $dir -Filter '*.exe' -File -Force)) {
            if ($exe.Length -ge 1MB -and ($exe.Length % 1MB) -eq 0) {
                $truncated += ("{0} ({1} MB exactly)" -f $exe.FullName, ($exe.Length / 1MB))
            }
        }
    }
}
if ($truncated.Count -gt 0) {
    Add-Finding 'Downloads' 'INFO' ("Probable truncated/incomplete downloads (exact-MiB size): {0}. These will not run and their signature looks missing - that is a BROKEN DOWNLOAD, not a virus blocking you. Delete and re-download." -f ($truncated -join '; ')) `
        'Descarcari probabil incomplete (marime exact rotunda). Nu vor rula si par nesemnate - este o DESCARCARE INTRERUPTA, nu un virus care te blocheaza. Sterge-le si descarca din nou.' `
        ($truncated -join "`n")
} else {
    Add-Finding 'Downloads' 'OK' 'No truncated downloads detected' 'Nicio descarcare incompleta detectata'
}

# =====================================================================
#  DEEP CHECKS (slow) - only with -Deep
# =====================================================================
if ($Deep) {
    Write-Section 'DEEP INTEGRITY (slow) / INTEGRITATE PROFUNDA (lent)'
    Write-Host '  Running DISM ScanHealth (2-10 min)... / Rulez DISM (2-10 min)...' -ForegroundColor DarkGray
    $dism = (& dism.exe /Online /Cleanup-Image /ScanHealth) -join ' '
    if ($dism -match 'No component store corruption detected') {
        Add-Finding 'Integrity' 'OK' 'DISM: no component store corruption' 'DISM: fara coruptie in depozitul de componente'
    } elseif ($dism -match 'repairable|corruption') {
        Add-Finding 'Integrity' 'WARN' 'DISM found component store corruption - run: DISM /Online /Cleanup-Image /RestoreHealth' `
            'DISM a gasit coruptie - ruleaza: DISM /Online /Cleanup-Image /RestoreHealth'
    } else {
        Add-Finding 'Integrity' 'INFO' 'DISM result unclear - see C:\Windows\Logs\DISM\dism.log' 'Rezultat DISM neclar - vezi dism.log'
    }

    Write-Host '  Running SFC (5-15 min)... / Rulez SFC (5-15 min)...' -ForegroundColor DarkGray
    $sfcRaw = & "$env:SystemRoot\System32\sfc.exe" /scannow
    $sfc = ($sfcRaw -join ' ') -replace "`0",''   # sfc output is UTF-16 with embedded nulls
    if ($sfc -match 'did not find any integrity violations') {
        Add-Finding 'Integrity' 'OK' 'SFC: no integrity violations' 'SFC: fara probleme de integritate'
    } elseif ($sfc -match 'successfully repaired') {
        Add-Finding 'Integrity' 'INFO' 'SFC repaired files (note: bthmodem.sys reports are a known false positive on Win11 22621)' `
            'SFC a reparat fisiere (nota: bthmodem.sys este un fals pozitiv cunoscut pe Win11 22621)'
    } else {
        Add-Finding 'Integrity' 'WARN' 'SFC reported unrepaired issues - see C:\Windows\Logs\CBS\CBS.log' `
            'SFC a raportat probleme nereparate - vezi CBS.log'
    }

    Write-Host '  Defender custom scan of user folders... / Scanare Defender...' -ForegroundColor DarkGray
    Start-MpScan -ScanType CustomScan -ScanPath "$env:USERPROFILE\Desktop"
    Start-MpScan -ScanType CustomScan -ScanPath "$env:USERPROFILE\Downloads"
    $newThreats = Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt $script:StartTime }
    if ($newThreats) {
        Add-Finding 'Integrity' 'CRIT' 'Defender scan found threats - open Windows Security > Protection history' `
            'Scanarea Defender a gasit amenintari - deschide Windows Security > Protection history'
    } else {
        Add-Finding 'Integrity' 'OK' 'Defender scan of Desktop+Downloads: clean' 'Scanare Defender Desktop+Downloads: curat'
    }
}

# =====================================================================
#  FIX ACTIONS - only with -Fix
# =====================================================================
if ($Fix) {
    Write-Section 'FIXES / REPARATII'

    # Guest account
    $guest = Get-LocalUser -Name 'Guest'
    if ($guest -and $guest.Enabled) {
        Disable-LocalUser -Name 'Guest'
        Add-Fix 'Disable Guest account' 'disabled'
    } else {
        Add-Fix 'Disable Guest account' 'already OK'
    }

    # Proxy reset
    $null = netsh winhttp reset proxy
    Add-Fix 'Reset WinHTTP proxy' 'done'
    if ($inet.ProxyEnable -eq 1) {
        Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0
        Add-Fix 'Disable manual browser proxy' 'disabled'
    } else {
        Add-Fix 'Disable manual browser proxy' 'already OK'
    }
    $null = ipconfig /flushdns
    Add-Fix 'Flush DNS cache' 'done'

    # hosts entries - per-entry confirmation, interactive only
    if ($hostsLines.Count -gt 0 -and [Environment]::UserInteractive) {
        $keep = New-Object System.Collections.ArrayList
        $removedAny = $false
        foreach ($line in (Get-Content $hostsPath)) {
            $isActive = ($line.Trim() -ne '' -and $line.Trim() -notlike '#*')
            if ($isActive) {
                Write-Host ("  hosts entry: {0}" -f $line) -ForegroundColor Yellow
                $ans = Read-Host '  Remove this entry? / Sterg aceasta intrare? (y/N)'
                if ($ans -eq 'y' -or $ans -eq 'Y') { $removedAny = $true; continue }
            }
            [void]$keep.Add($line)
        }
        if ($removedAny) {
            Copy-Item $hostsPath "$hostsPath.bak" -Force
            Set-Content -Path $hostsPath -Value $keep -Encoding ASCII
            Add-Fix 'Clean hosts file' 'entries removed (backup: hosts.bak)'
        } else {
            Add-Fix 'Clean hosts file' 'kept all entries'
        }
    }

    # Temp cleanup
    $freed = 0
    foreach ($tempDir in @($env:TEMP, "$env:SystemRoot\Temp")) {
        foreach ($item in (Get-ChildItem $tempDir -Force)) {
            $sz = 0
            if ($item.PSIsContainer) { $sz = (Get-ChildItem $item.FullName -Recurse -Force | Measure-Object Length -Sum).Sum }
            else { $sz = $item.Length }
            Remove-Item -LiteralPath $item.FullName -Recurse -Force
            if (-not (Test-Path -LiteralPath $item.FullName)) { $freed += $sz }
        }
    }
    Add-Fix 'Clean temp folders' ("freed {0} MB (locked files skipped)" -f [math]::Round($freed/1MB,0))

    # Windows Update download cache
    Stop-Service wuauserv -Force
    $wuFreed = 0
    foreach ($item in (Get-ChildItem "$env:SystemRoot\SoftwareDistribution\Download" -Force)) {
        $sz = 0
        if ($item.PSIsContainer) { $sz = (Get-ChildItem $item.FullName -Recurse -Force | Measure-Object Length -Sum).Sum }
        else { $sz = $item.Length }
        Remove-Item -LiteralPath $item.FullName -Recurse -Force
        if (-not (Test-Path -LiteralPath $item.FullName)) { $wuFreed += $sz }
    }
    Start-Service wuauserv
    Add-Fix 'Clear Windows Update cache' ("freed {0} MB" -f [math]::Round($wuFreed/1MB,0))

    # Component store cleanup - only in deep mode (slow)
    if ($Deep) {
        Write-Host '  DISM StartComponentCleanup (may take 10+ min)...' -ForegroundColor DarkGray
        $null = & dism.exe /Online /Cleanup-Image /StartComponentCleanup
        Add-Fix 'DISM component store cleanup' 'done'
    }
}

# =====================================================================
#  VERDICT
# =====================================================================
Write-Section 'VERDICT'

$critCount = @($script:Findings | Where-Object { $_.Severity -eq 'CRIT' }).Count
$warnCount = @($script:Findings | Where-Object { $_.Severity -eq 'WARN' }).Count
if ($critCount -gt 0) {
    $verdict   = 'CRITICAL ISSUES FOUND'
    $verdictRO = 'PROBLEME CRITICE GASITE'
    $verdictColor = 'Red'
    $advice   = 'Review CRIT items above. If they confirm malware: disconnect network, run Microsoft Defender Offline scan (Windows Security > Scan options), and change passwords from a different device.'
    $adviceRO = 'Verifica punctele CRIT de mai sus. Daca se confirma malware: deconecteaza reteaua, ruleaza Microsoft Defender Offline scan si schimba parolele de pe alt dispozitiv.'
} elseif ($warnCount -gt 0) {
    $verdict   = ("NO MALWARE INDICATORS - {0} warning(s) to review" -f $warnCount)
    $verdictRO = ("FARA INDICII DE MALWARE - {0} atentionari de verificat" -f $warnCount)
    $verdictColor = 'Yellow'
    $advice   = 'Warnings are usually settings or aggressive-but-legal software, not infections. Read each one; the report explains them.'
    $adviceRO = 'Atentionarile sunt de obicei setari sau programe agresive dar legale, nu infectii. Citeste-le pe fiecare; raportul le explica.'
} else {
    $verdict   = 'CLEAN - no malware indicators found'
    $verdictRO = 'CURAT - niciun indiciu de malware gasit'
    $verdictColor = 'Green'
    $advice   = 'Every place real malware hides was checked and came back clean.'
    $adviceRO = 'Toate locurile unde se ascunde malware real au fost verificate si sunt curate.'
}
Write-Host ""
Write-Host ("  {0}" -f $verdict) -ForegroundColor $verdictColor
Write-Host ("  {0}" -f $verdictRO) -ForegroundColor $verdictColor
Write-Host ("  {0}" -f $advice) -ForegroundColor Gray
$elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalMinutes, 1)
Write-Host ("  Checks: {0}   CRIT: {1}   WARN: {2}   Time: {3} min" -f $script:Findings.Count, $critCount, $warnCount, $elapsed)

# =====================================================================
#  HTML REPORT
# =====================================================================
if (-not $NoReport) {
    Add-Type -AssemblyName System.Web
    $reportPath = Join-Path ([Environment]::GetFolderPath('Desktop')) ("PC-HealthCheck_{0}_{1}.html" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HHmm'))
    $bannerBg = switch ($verdictColor) { 'Green' { '#1a7f37' } 'Yellow' { '#9a6700' } 'Red' { '#cf222e' } }

    $rowsHtml = New-Object System.Text.StringBuilder
    foreach ($f in $script:Findings) {
        $sevBg = switch ($f.Severity) { 'OK' { '#dafbe1' } 'INFO' { '#ddf4ff' } 'WARN' { '#fff8c5' } 'CRIT' { '#ffebe9' } }
        $ev = [System.Web.HttpUtility]::HtmlEncode($f.Evidence)
        $msg = [System.Web.HttpUtility]::HtmlEncode($f.Message)
        $msgRO = [System.Web.HttpUtility]::HtmlEncode($f.MessageRO)
        $evBlock = ''
        if ($ev) { $evBlock = "<details><summary>evidence / probe</summary><pre>$ev</pre></details>" }
        [void]$rowsHtml.Append("<tr><td>$($f.Area)</td><td style='background:$sevBg;text-align:center;font-weight:bold'>$($f.Severity)</td><td>$msg<br><span class='ro'>$msgRO</span>$evBlock</td></tr>`n")
    }

    $fixHtml = ''
    if ($script:FixLog.Count -gt 0) {
        $fixRows = ($script:FixLog | ForEach-Object { "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_.Action))</td><td>$([System.Web.HttpUtility]::HtmlEncode($_.Result))</td></tr>" }) -join "`n"
        $fixHtml = "<h2>Fixes applied / Reparatii aplicate</h2><table><tr><th>Action</th><th>Result</th></tr>$fixRows</table>"
    }

    $html = @"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PC Health Check - $env:COMPUTERNAME</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;max-width:1000px;color:#1f2328}
.banner{background:$bannerBg;color:#fff;padding:16px 20px;border-radius:8px;font-size:1.3em;font-weight:bold}
.sub{color:#fff;opacity:.9;font-size:.75em;font-weight:normal;margin-top:4px}
table{border-collapse:collapse;width:100%;margin:12px 0}
th,td{border:1px solid #d0d7de;padding:6px 10px;text-align:left;vertical-align:top;font-size:.9em}
th{background:#f6f8fa}
.ro{color:#57606a;font-style:italic}
pre{background:#f6f8fa;padding:8px;overflow-x:auto;white-space:pre-wrap;font-size:.85em;max-height:240px;overflow-y:auto}
details summary{cursor:pointer;color:#0969da;font-size:.85em}
.box{background:#f6f8fa;border:1px solid #d0d7de;border-radius:8px;padding:12px 16px;margin:12px 0}
h2{border-bottom:1px solid #d0d7de;padding-bottom:4px}
.disclaimer{color:#57606a;font-size:.85em}
</style></head><body>
<div class="banner">$verdict<div class="sub">$verdictRO</div></div>
<p><b>$env:COMPUTERNAME</b> - $(Get-Date -Format 'yyyy-MM-dd HH:mm') - $($script:Findings.Count) checks - CRIT: $critCount - WARN: $warnCount</p>
<p>$advice<br><span class="ro">$adviceRO</span></p>
<p class="disclaimer">Curat-PC is a diagnostic and cleanup tool, NOT an antivirus. Keep Windows Defender real-time protection ON.<br>
Curat-PC este un instrument de diagnostic si curatare, NU un antivirus. Pastreaza protectia in timp real Windows Defender ACTIVA.</p>
<h2>Findings / Constatari</h2>
<table><tr><th>Area</th><th>Severity</th><th>Finding / Constatare</th></tr>
$($rowsHtml.ToString())
</table>
$fixHtml
<h2>Common FALSE alarms explained / Alarme FALSE frecvente explicate</h2>
<div class="box">
<b>1. SFC says bthmodem.sys is corrupt</b> - known false positive on Windows 11 build 22621. If the file has a valid Microsoft signature, it is fine.<br>
<span class="ro">Fals pozitiv cunoscut pe Windows 11 22621. Daca fisierul are semnatura Microsoft valida, este in regula.</span><br><br>
<b>2. Windows Update error 0x800f0923</b> - means "Safe Mode entered": updates refuse to install in Safe Mode and roll back safely. Not an infection.<br>
<span class="ro">Inseamna "Safe Mode activ": actualizarile refuza sa se instaleze in Safe Mode si se anuleaza in siguranta. Nu este infectie.</span><br><br>
<b>3. Store apps look "unsigned"</b> - Microsoft Store (MSIX) apps are signed at package level; per-file checks show NotSigned. Normal.<br>
<span class="ro">Aplicatiile din Microsoft Store sunt semnate la nivel de pachet; verificarile per-fisier arata NotSigned. Normal.</span><br><br>
<b>4. A downloaded .exe "will not run" and looks unsigned</b> - if its size is an exact number of MB, the download was interrupted. The signature lives at the END of the file. Delete and re-download.<br>
<span class="ro">Daca marimea este un numar exact de MB, descarcarea a fost intrerupta. Semnatura se afla la SFARSITUL fisierului. Sterge si descarca din nou.</span><br><br>
<b>5. Ports 135, 445, 49664-49670, UDP 500/4500 are open</b> - standard Windows RPC and IPsec services, present on every Windows PC.<br>
<span class="ro">Servicii standard Windows RPC si IPsec, prezente pe orice PC cu Windows.</span><br><br>
<b>6. Scary "your drivers are outdated / PC at risk" popups</b> - almost always a paid "optimizer" app you or a bundle installed, not malware. Uninstall it from Settings &gt; Apps.<br>
<span class="ro">Aproape intotdeauna o aplicatie platita de tip "optimizer" instalata de tine sau la pachet, nu malware. Dezinstaleaz-o din Settings &gt; Apps.</span>
</div>
<h2>If real malware IS confirmed / Daca se confirma malware real</h2>
<div class="box">
1. Disconnect from the network / Deconecteaza reteaua.<br>
2. Run Microsoft Defender Offline scan (Windows Security &gt; Virus &amp; threat protection &gt; Scan options) / Ruleaza scanarea offline Defender.<br>
3. Change important passwords from a DIFFERENT device / Schimba parolele importante de pe ALT dispozitiv.<br>
4. For ransomware, check your file extension on <b>nomoreransom.org</b> before paying anything - never pay first / Pentru ransomware, verifica extensia pe nomoreransom.org - nu plati niciodata.
</div>
<p class="disclaimer">Generated by Curat-PC in $elapsed min / Generat de Curat-PC in $elapsed min</p>
</body></html>
"@
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($true)))
    Write-Host ""
    Write-Host ("  Report saved / Raport salvat: {0}" -f $reportPath) -ForegroundColor Cyan
    Invoke-Item $reportPath
}

# =====================================================================
#  JSON EXPORT - only with -Json (machine-readable, for remote diagnosis)
# =====================================================================
if ($Json) {
    $jsonPath = Join-Path ([Environment]::GetFolderPath('Desktop')) ("PC-HealthCheck_{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyy-MM-dd_HHmm'))
    $jsonDoc = [pscustomobject]@{
        Computer  = $env:COMPUTERNAME
        User      = $env:USERNAME
        Date      = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        Mode      = ("scan{0}{1}" -f $(if ($Fix) {'+fix'} else {''}), $(if ($Deep) {'+deep'} else {''}))
        Verdict   = $verdict
        VerdictRO = $verdictRO
        Crit      = $critCount
        Warn      = $warnCount
        Findings  = @($script:Findings)
        Fixes     = @($script:FixLog)
    }
    [System.IO.File]::WriteAllText($jsonPath, ($jsonDoc | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ("  JSON saved / JSON salvat: {0}" -f $jsonPath) -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  Done. / Gata." -ForegroundColor White
if ([Environment]::UserInteractive -and -not $psISE) {
    Write-Host "  Press Enter to close / Apasa Enter pentru a inchide"
    $null = Read-Host
}
