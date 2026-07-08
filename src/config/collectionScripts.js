/*
 * ============================================================================
 * COLLECTION SCRIPTS — fully-custom, no third-party tools
 * ============================================================================
 *
 * Some endpoint data is not sitting in a simple file you can copy: it is live
 * system state (registry, service manager, kernel journal). For those sources
 * the analyst runs one of these native scripts on the host — built only from
 * OS built-ins (PowerShell, systemctl, journalctl), never a third-party DFIR
 * tool — and imports the CSV it writes.
 *
 * Every script emits a CSV whose header row is exactly the category's field
 * keys (name/kind/command/location, device/serial/vendor/connection, …), so it
 * round-trips through the importer 1:1.
 *
 * Strings use String.raw so Windows backslash paths survive verbatim. Avoid
 * bash `${...}` parameter-expansion braces (they collide with template
 * interpolation) — use sed/`$var` instead.
 */

const ps = (code) => ({ lang: 'powershell', code: code.trim() })
const sh = (code) => ({ lang: 'bash', code: code.trim() })

/* ------------------------------- Execution ------------------------------- */

export const EXEC_WIN_BAM = ps(String.raw`
# BAM/DAM last-execution — native, no external tools. → execution_bam.csv
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

/* ------------------------------ Persistence ------------------------------ */

export const PERS_WIN_RUN = ps(String.raw`
# Run/RunOnce keys — native. → persistence_runkeys.csv
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
# Scheduled Tasks — native. → persistence_tasks.csv
Get-ScheduledTask | ForEach-Object {
  $cmd = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; '
  [pscustomobject]@{ name = $_.TaskName; kind = 'Scheduled Task'; command = $cmd; location = $_.TaskPath }
} | Export-Csv .\persistence_tasks.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_SERVICES = ps(String.raw`
# Services — native. → persistence_services.csv
Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{ name = $_.Name; kind = 'Service'; command = $_.PathName; location = $_.StartMode }
} | Export-Csv .\persistence_services.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_STARTUP = ps(String.raw`
# Startup folder — native. → persistence_startup.csv
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -File -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ name = $_.Name; kind = 'Startup folder'; command = $_.FullName; location = $_.DirectoryName } } |
  Export-Csv .\persistence_startup.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_WIN_WMI = ps(String.raw`
# WMI event subscriptions — native (root\Subscription). → persistence_wmi.csv
Get-WmiObject -Namespace root\Subscription -Class __EventFilter -ErrorAction SilentlyContinue |
  ForEach-Object { [pscustomobject]@{ name = $_.Name; kind = 'WMI filter'; command = $_.Query; location = 'root\Subscription' } } |
  Export-Csv .\persistence_wmi.csv -NoTypeInformation -Encoding UTF8
`)

export const PERS_LINUX_SYSTEMD = sh(String.raw`
#!/bin/sh
# enabled systemd services — native (systemctl). → persistence_systemd.csv
{ echo 'name,kind,command,location'
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null \
    | awk '{printf "\"%s\",\"systemd\",\"\",\"%s\"\n", $1, $1}'
} > persistence_systemd.csv
`)

/* ------------------------------ USB & devices ---------------------------- */

export const USB_WIN_USBSTOR = ps(String.raw`
# USBSTOR devices — native (registry). → usb_usbstor.csv
$out = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object {
  $model = $_.PSChildName
  Get-ChildItem $_.PSPath | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [pscustomobject]@{ device = $p.FriendlyName; serial = $_.PSChildName; vendor = $model; connection = 'USBSTOR' }
  }
}
$out | Export-Csv .\usb_usbstor.csv -NoTypeInformation -Encoding UTF8
`)

export const USB_LINUX_JOURNAL = sh(String.raw`
#!/bin/sh
# USB device events from the kernel journal — native (journalctl). → usb_kernel.csv
{ echo 'device,serial,vendor,connection'
  journalctl -k --no-pager 2>/dev/null \
    | grep -iE 'New USB device found|Product:|Manufacturer:|SerialNumber:' \
    | while IFS= read -r line; do
        esc=$(printf '%s' "$line" | sed 's/"/""/g')
        printf '"%s","","","kernel"\n' "$esc"
      done
} > usb_kernel.csv
`)
