/*
 * ============================================================================
 * COLLECTION SCRIPTS — run on the target host to produce an importable CSV
 * ============================================================================
 *
 * Several endpoint artifacts are not files you can just copy: they live in
 * registry hives, journals or need a parser. For those, the analyst runs a
 * small script/command on the target host that writes a CSV, then imports that
 * CSV here. Each script is attached to a source in config/artifacts.js and
 * shown (copy + download) in the "where to find it" note.
 *
 * NATIVE scripts emit a CSV whose header row is exactly the category's field
 * keys (name/path/…), so the lenient importer maps them 1:1. TOOL commands
 * invoke an external DFIR parser (Eric Zimmerman's tools, auditd, …) whose
 * columns are caught by the broadened aliases in config/artifacts.js.
 *
 * Strings use String.raw so Windows backslash paths survive verbatim. Avoid
 * bash `${...}` parameter-expansion braces here (they collide with template
 * interpolation) — use sed/`$var` instead.
 *
 * A script is { lang: 'powershell' | 'bash', code: string }.
 */

const ps = (code) => ({ lang: 'powershell', code: code.trim() })
const sh = (code) => ({ lang: 'bash', code: code.trim() })

/* ------------------------------- Execution ------------------------------- */

export const EXEC_WIN_PREFETCH = ps(String.raw`
# Prefetch — requires PECmd (Eric Zimmerman's tools) on the analysis box.
# Point -d at the collected Prefetch folder, then import the CSV here.
.\PECmd.exe -d C:\Windows\Prefetch --csv . --csvf execution_prefetch.csv
`)

export const EXEC_WIN_AMCACHE = ps(String.raw`
# Amcache — requires AmcacheParser (Eric Zimmerman's tools).
.\AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv . --csvf execution_amcache.csv
`)

export const EXEC_WIN_SHIMCACHE = ps(String.raw`
# ShimCache / AppCompatCache — requires AppCompatCacheParser (EZ tools).
.\AppCompatCacheParser.exe --csv . --csvf execution_shimcache.csv
`)

export const EXEC_WIN_USERASSIST = ps(String.raw`
# UserAssist — requires RECmd (EZ tools) with the UserActivity batch.
.\RECmd.exe -f "$env:USERPROFILE\NTUSER.DAT" --bn BatchExamples\UserActivity.reb --csv .
`)

export const EXEC_WIN_BAM = ps(String.raw`
# BAM/DAM — native collector, no external tools. Produces execution_bam.csv.
$out = foreach ($base in @(
  'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
  'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings')) {
  if (-not (Test-Path $base)) { continue }
  Get-ChildItem $base | ForEach-Object {
    $k = Get-Item $_.PSPath
    foreach ($name in $k.Property) {
      if ($name -notmatch '\.exe$') { continue }
      [pscustomobject]@{ name = Split-Path $name -Leaf; path = $name; runCount = ''; source = 'BAM' }
    }
  }
}
$out | Export-Csv .\execution_bam.csv -NoTypeInformation -Encoding UTF8
`)

export const EXEC_LINUX_AUDITD = sh(String.raw`
# Program execution — requires auditd with EXECVE rules. Newer audit emits CSV.
sudo ausearch -m EXECVE --start today --format csv 2>/dev/null > execution_auditd.csv
`)

export const EXEC_MAC_KNOWLEDGEC = sh(String.raw`
# App usage from KnowledgeC (may require Full Disk Access). → execution_knowledgec.csv
sqlite3 -header -csv "$HOME/Library/Application Support/Knowledge/knowledgeC.db" \
  "SELECT ZVALUESTRING AS name, ZVALUESTRING AS path, datetime(ZSTARTDATE+978307200,'unixepoch') AS lastRun \
   FROM ZOBJECT WHERE ZSTREAMNAME='/app/usage' ORDER BY ZSTARTDATE DESC;" > execution_knowledgec.csv
`)

/* ------------------------------ Persistence ------------------------------ */

export const PERS_WIN_RUN = ps(String.raw`
# Run/RunOnce keys — native. Produces persistence_runkeys.csv.
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
$out = foreach ($k in $keys) {
  if (-not (Test-Path $k)) { continue }
  $p = Get-ItemProperty $k
  $p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
    [pscustomobject]@{ name = $_.Name; kind = 'Run key'; command = $_.Value; location = $k }
  }
}
$out | Export-Csv .\persistence_runkeys.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_TASKS = ps(String.raw`
# Scheduled Tasks — native. Produces persistence_tasks.csv.
Get-ScheduledTask | ForEach-Object {
  $cmd = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; '
  [pscustomobject]@{ name = $_.TaskName; kind = 'Scheduled Task'; command = $cmd; location = $_.TaskPath }
} | Export-Csv .\persistence_tasks.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_SERVICES = ps(String.raw`
# Services — native. Produces persistence_services.csv.
Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; kind = 'Service'; command = $_.PathName; location = $_.StartMode }
} | Export-Csv .\persistence_services.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_STARTUP = ps(String.raw`
# Startup folder — native. Produces persistence_startup.csv.
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -File -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ name = $_.Name; kind = 'Startup folder'; command = $_.FullName; location = $_.DirectoryName } } |
  Export-Csv .\persistence_startup.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_WMI = ps(String.raw`
# WMI event subscriptions — native (root\Subscription).
Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ name = $_.Name; kind = 'WMI filter'; command = $_.Query; location = 'root\Subscription' } } |
  Export-Csv .\persistence_wmi.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_LINUX_CRON = sh(String.raw`
#!/bin/sh
# cron persistence → persistence_cron.csv
{ echo 'name,kind,command,location'
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" | while IFS= read -r line; do
      esc=$(printf '%s' "$line" | sed 's/"/""/g')
      printf '"%s","cron","%s","%s"\n' "$(basename "$f")" "$esc" "$f"
    done
  done
} > persistence_cron.csv
`)

export const PERS_LINUX_SYSTEMD = sh(String.raw`
#!/bin/sh
# enabled systemd services → persistence_systemd.csv
{ echo 'name,kind,command,location'
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null \
    | awk '{printf "\"%s\",\"systemd\",\"\",\"%s\"\n", $1, $1}'
} > persistence_systemd.csv
`)

export const PERS_LINUX_SSHKEYS = sh(String.raw`
#!/bin/sh
# SSH authorized_keys → persistence_sshkeys.csv
{ echo 'name,kind,command,location'
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [ -f "$f" ] || continue
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      esc=$(printf '%s' "$line" | sed 's/"/""/g')
      printf '"authorized_key","authorized_keys","%s","%s"\n' "$esc" "$f"
    done < "$f"
  done
} > persistence_sshkeys.csv
`)

export const PERS_LINUX_RC = sh(String.raw`
#!/bin/sh
# shell rc / profile hooks → persistence_rc.csv
{ echo 'name,kind,command,location'
  for f in /etc/rc.local "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile" "$HOME/.zshrc"; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" | while IFS= read -r line; do
      esc=$(printf '%s' "$line" | sed 's/"/""/g')
      printf '"%s","shell rc","%s","%s"\n' "$(basename "$f")" "$esc" "$f"
    done
  done
} > persistence_rc.csv
`)

export const PERS_MAC_LAUNCH = sh(String.raw`
#!/bin/sh
# LaunchAgents/Daemons → persistence_launch.csv
{ echo 'name,kind,command,location'
  for d in "$HOME/Library/LaunchAgents" /Library/LaunchAgents /Library/LaunchDaemons; do
    [ -d "$d" ] || continue
    for p in "$d"/*.plist; do
      [ -f "$p" ] || continue
      prog=$(/usr/bin/defaults read "$p" ProgramArguments 2>/dev/null | tr '\n' ' ' | sed 's/"/""/g')
      printf '"%s","LaunchAgent","%s","%s"\n' "$(basename "$p")" "$prog" "$p"
    done
  done
} > persistence_launch.csv
`)

export const PERS_MAC_CRON = sh(String.raw`
#!/bin/sh
# per-user cron → persistence_cron.csv
{ echo 'name,kind,command,location'
  for f in /usr/lib/cron/tabs/*; do
    [ -f "$f" ] || continue
    grep -vE '^[[:space:]]*#|^[[:space:]]*$' "$f" | while IFS= read -r line; do
      esc=$(printf '%s' "$line" | sed 's/"/""/g')
      printf '"%s","cron","%s","%s"\n' "$(basename "$f")" "$esc" "$f"
    done
  done
} > persistence_cron.csv
`)

/* ---------------------------- File & folder ------------------------------ */

export const FA_WIN_LNK = ps(String.raw`
# LNK shortcuts — requires LECmd (EZ tools).
.\LECmd.exe -d "$env:APPDATA\Microsoft\Windows\Recent" --csv . --csvf fileaccess_lnk.csv
`)

export const FA_WIN_JUMPLISTS = ps(String.raw`
# JumpLists — requires JLECmd (EZ tools).
.\JLECmd.exe -d "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" --csv . --csvf fileaccess_jumplists.csv
`)

export const FA_WIN_SHELLBAGS = ps(String.raw`
# ShellBags — requires SBECmd (EZ tools). Point -d at the extracted profile.
.\SBECmd.exe -d "$env:USERPROFILE" --csv .
`)

export const FA_WIN_RECENTDOCS = ps(String.raw`
# RecentDocs — requires RECmd (EZ tools) with the RecentDocs batch.
.\RECmd.exe -f "$env:USERPROFILE\NTUSER.DAT" --bn BatchExamples\RecentDocs.reb --csv .
`)

export const FA_LINUX_RECENT = sh(String.raw`
#!/bin/sh
# GTK recently-used → fileaccess_recent.csv
f="$HOME/.local/share/recently-used.xbel"
{ echo 'name,target,kind'
  [ -f "$f" ] && grep -oE 'href="[^"]+"' "$f" | sed 's/href="//; s/"$//' | while IFS= read -r u; do
    p=$(printf '%s' "$u" | sed 's|^file://||')
    printf '"%s","%s","recently-used"\n' "$(basename "$p")" "$p"
  done
} > fileaccess_recent.csv
`)

export const FA_MAC_RECENT = sh(String.raw`
#!/bin/sh
# Finder recent folders snapshot (sfl needs a dedicated parser for full history).
defaults read com.apple.finder FXRecentFolders 2>/dev/null > fileaccess_recent.txt
`)

/* ------------------------------ USB & devices ---------------------------- */

export const USB_WIN_USBSTOR = ps(String.raw`
# USBSTOR devices — native. Produces usb_usbstor.csv.
$out = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object {
  $model = $_.PSChildName
  Get-ChildItem $_.PSPath | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [pscustomobject]@{ device = $p.FriendlyName; serial = $_.PSChildName; vendor = $model; connection = 'USBSTOR' }
  }
}
$out | Export-Csv .\usb_usbstor.csv -NoTypeInformation -Encoding UTF8
`)

export const USB_WIN_SETUPAPI = ps(String.raw`
# First-insertion evidence from the setupapi log → usb_setupapi.csv
Select-String -Path C:\Windows\INF\setupapi.dev.log -Pattern 'USBSTOR|USB\\VID' |
  ForEach-Object { [pscustomobject]@{ device = $_.Line.Trim(); serial = ''; vendor = ''; connection = 'setupapi' } } |
  Export-Csv .\usb_setupapi.csv -NoTypeInformation -Encoding UTF8
`)

export const USB_LINUX_JOURNAL = sh(String.raw`
#!/bin/sh
# USB device events from the kernel journal → usb_kernel.csv (best-effort)
{ echo 'device,serial,vendor,connection'
  journalctl -k --no-pager 2>/dev/null \
    | grep -iE 'New USB device found|Product:|Manufacturer:|SerialNumber:' \
    | while IFS= read -r line; do
        esc=$(printf '%s' "$line" | sed 's/"/""/g')
        printf '"%s","","","kernel"\n' "$esc"
      done
} > usb_kernel.csv
`)

export const USB_MAC_PROFILER = sh(String.raw`
#!/bin/sh
# Connected USB devices snapshot (history needs unified logs).
system_profiler SPUSBDataType 2>/dev/null > usb_devices.txt
`)
