/*
 * ============================================================================
 * WINDOWS EVENT LOGS — channels and curated event IDs
 * ============================================================================
 *
 * A Windows host writes thousands of events an hour; only a few dozen ids
 * matter to an investigation. This catalog lists them, per channel, with a
 * label, a category and a one-line summary built from the event's fields.
 *
 * Event logs come in two ways (Event Logs tab):
 *   - the raw `.evtx` files, uploaded and parsed ON THE SERVER (a binary
 *     format the browser cannot read; see backend/app/parsing/eventlog.py);
 *   - the JSON written by the collection script below (Get-WinEvent, native),
 *     parsed in the browser.
 * Both keep only the curated ids. CURATED_EVENTS is mirrored by CURATED in
 * backend/app/parsing/eventlog.py; a unit test compares the two.
 */

export const LOGON_TYPES = {
  2: 'interactive',
  3: 'network',
  4: 'batch',
  5: 'service',
  7: 'unlock',
  8: 'network cleartext',
  9: 'new credentials',
  10: 'RDP',
  11: 'cached interactive',
}

/** Logon types a person is behind (console, RDP, unlock, cached). */
export const HUMAN_LOGON_TYPES = new Set(['2', '7', '10', '11'])

/** Event categories: filter values and badge colors. */
export const EVENT_CATEGORIES = {
  logon: { label: 'Logon', color: 'cyan' },
  account: { label: 'Account', color: 'violet' },
  process: { label: 'Process', color: 'emerald' },
  service: { label: 'Service', color: 'amber' },
  task: { label: 'Scheduled task', color: 'amber' },
  powershell: { label: 'PowerShell', color: 'violet' },
  rdp: { label: 'RDP', color: 'cyan' },
  defender: { label: 'Defender', color: 'red' },
  log: { label: 'Audit / log', color: 'red' },
  system: { label: 'System', color: 'slate' },
  network: { label: 'Network', color: 'slate' },
}

const v = (d, ...keys) => {
  for (const key of keys) if (d?.[key]) return d[key]
  return ''
}
const who = (d, prefix = 'Target') => {
  const user = v(d, `${prefix}UserName`)
  const domain = v(d, `${prefix}DomainName`)
  return user ? (domain && !user.endsWith('$') ? `${domain}\\${user}` : user) : '?'
}
const logonType = (d) => LOGON_TYPES[d?.LogonType] ?? `type ${d?.LogonType ?? '?'}`
const from = (d) => {
  const ip = v(d, 'IpAddress')
  const ws = v(d, 'WorkstationName')
  const source = [ws, ip && ip !== '::1' && ip !== '127.0.0.1' ? ip : ''].filter(Boolean).join(' / ')
  return source ? ` from ${source}` : ''
}
const short = (text, max = 160) => {
  const one = String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim()
  return one.length > max ? `${one.slice(0, max - 1)}…` : one
}

/*
 * Channels, in display order. `key` is the lower-case channel name (the match
 * key); `name` its canonical spelling; `events` the curated ids:
 *   { label, category, summary(data) → string, user?(data) → string }
 */
export const EVENT_CHANNELS = [
  {
    key: 'security',
    name: 'Security',
    short: 'Security',
    file: 'Security.evtx',
    events: {
      1102: { label: 'Audit log cleared', category: 'log', summary: (d) => `cleared by ${who(d, 'Subject')}` },
      4624: {
        label: 'Logon',
        category: 'logon',
        summary: (d) => `${who(d)} — ${logonType(d)}${from(d)}`,
      },
      4625: {
        label: 'Failed logon',
        category: 'logon',
        summary: (d) => `${who(d)} — ${logonType(d)}${from(d)}`,
      },
      4634: { label: 'Logoff', category: 'logon', summary: (d) => `${who(d)} — ${logonType(d)}` },
      4647: { label: 'User logoff', category: 'logon', summary: (d) => who(d) },
      4648: {
        label: 'Explicit credentials',
        category: 'logon',
        summary: (d) => `${who(d, 'Subject')} as ${who(d)} → ${v(d, 'TargetServerName') || '?'}`,
      },
      4672: { label: 'Admin privileges', category: 'logon', summary: (d) => who(d, 'Subject') },
      4688: {
        label: 'Process created',
        category: 'process',
        summary: (d) => short(v(d, 'CommandLine', 'NewProcessName')),
        user: (d) => who(d, 'Subject'),
      },
      4697: {
        label: 'Service installed',
        category: 'service',
        summary: (d) => `${v(d, 'ServiceName')} → ${short(v(d, 'ServiceFileName'))}`,
        user: (d) => who(d, 'Subject'),
      },
      4698: {
        label: 'Task created',
        category: 'task',
        summary: (d) => v(d, 'TaskName'),
        user: (d) => who(d, 'Subject'),
      },
      4699: {
        label: 'Task deleted',
        category: 'task',
        summary: (d) => v(d, 'TaskName'),
        user: (d) => who(d, 'Subject'),
      },
      4702: {
        label: 'Task updated',
        category: 'task',
        summary: (d) => v(d, 'TaskName'),
        user: (d) => who(d, 'Subject'),
      },
      4719: { label: 'Audit policy changed', category: 'log', summary: (d) => `by ${who(d, 'Subject')}` },
      4720: { label: 'Account created', category: 'account', summary: (d) => `${who(d)} by ${who(d, 'Subject')}` },
      4722: { label: 'Account enabled', category: 'account', summary: (d) => `${who(d)} by ${who(d, 'Subject')}` },
      4724: { label: 'Password reset', category: 'account', summary: (d) => `${who(d)} by ${who(d, 'Subject')}` },
      4726: { label: 'Account deleted', category: 'account', summary: (d) => `${who(d)} by ${who(d, 'Subject')}` },
      4728: {
        label: 'Added to global group',
        category: 'account',
        summary: (d) => `${v(d, 'MemberName', 'MemberSid')} → ${v(d, 'TargetUserName')}`,
        user: (d) => who(d, 'Subject'),
      },
      4732: {
        label: 'Added to local group',
        category: 'account',
        summary: (d) => `${v(d, 'MemberName', 'MemberSid')} → ${v(d, 'TargetUserName')}`,
        user: (d) => who(d, 'Subject'),
      },
      4740: { label: 'Account locked out', category: 'account', summary: (d) => `${who(d)}${from(d)}` },
      4756: {
        label: 'Added to universal group',
        category: 'account',
        summary: (d) => `${v(d, 'MemberName', 'MemberSid')} → ${v(d, 'TargetUserName')}`,
        user: (d) => who(d, 'Subject'),
      },
      4771: {
        label: 'Kerberos pre-auth failed',
        category: 'logon',
        summary: (d) => `${who(d)}${from(d)}`,
      },
      4776: {
        label: 'NTLM validation',
        category: 'logon',
        summary: (d) => `${v(d, 'TargetUserName')} from ${v(d, 'Workstation') || '?'} (status ${v(d, 'Status')})`,
        user: (d) => v(d, 'TargetUserName'),
      },
      4778: {
        label: 'Session reconnected',
        category: 'rdp',
        summary: (d) => `${v(d, 'AccountName')} from ${v(d, 'ClientName')} ${v(d, 'ClientAddress')}`.trim(),
        user: (d) => v(d, 'AccountName'),
      },
      4779: {
        label: 'Session disconnected',
        category: 'rdp',
        summary: (d) => `${v(d, 'AccountName')} from ${v(d, 'ClientName')} ${v(d, 'ClientAddress')}`.trim(),
        user: (d) => v(d, 'AccountName'),
      },
    },
  },
  {
    key: 'system',
    name: 'System',
    short: 'System',
    file: 'System.evtx',
    events: {
      104: {
        label: 'Event log cleared',
        category: 'log',
        summary: (d) => `${v(d, 'Channel') || 'a log'} cleared by ${v(d, 'SubjectUserName') || '?'}`,
        user: (d) => v(d, 'SubjectUserName'),
      },
      1074: {
        label: 'Shutdown / restart',
        category: 'system',
        summary: (d) => short(`${v(d, 'param5', 'Data5')} by ${v(d, 'param7', 'Data7')} (${v(d, 'param1', 'Data1')})`),
      },
      6005: { label: 'Event log started (boot)', category: 'system', summary: () => 'boot' },
      6006: { label: 'Event log stopped (shutdown)', category: 'system', summary: () => 'clean shutdown' },
      6008: { label: 'Unexpected shutdown', category: 'system', summary: () => 'previous shutdown was unexpected' },
      7040: {
        label: 'Service start type changed',
        category: 'service',
        summary: (d) => `${v(d, 'param1', 'Data1')}: ${v(d, 'param2', 'Data2')} → ${v(d, 'param3', 'Data3')}`,
      },
      7045: {
        label: 'Service installed',
        category: 'service',
        summary: (d) => `${v(d, 'ServiceName')} → ${short(v(d, 'ImagePath'))}`,
        user: (d) => v(d, 'AccountName'),
      },
    },
  },
  {
    key: 'microsoft-windows-powershell/operational',
    name: 'Microsoft-Windows-PowerShell/Operational',
    short: 'PowerShell',
    file: 'Microsoft-Windows-PowerShell%4Operational.evtx',
    events: {
      4103: {
        label: 'Module logging',
        category: 'powershell',
        summary: (d) => short(v(d, 'Payload', 'ContextInfo')),
      },
      4104: {
        label: 'Script block',
        category: 'powershell',
        summary: (d) => short(v(d, 'ScriptBlockText')),
      },
    },
  },
  {
    key: 'windows powershell',
    name: 'Windows PowerShell',
    short: 'PowerShell (classic)',
    file: 'Windows PowerShell.evtx',
    events: {
      400: {
        label: 'Engine started',
        category: 'powershell',
        summary: (d) => short(hostApplication(d)),
      },
      800: {
        label: 'Pipeline executed',
        category: 'powershell',
        summary: (d) => short(v(d, 'Data1') || hostApplication(d)),
      },
    },
  },
  {
    key: 'microsoft-windows-terminalservices-localsessionmanager/operational',
    name: 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
    short: 'RDP sessions',
    file: 'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
    events: {
      21: { label: 'RDP logon', category: 'rdp', summary: (d) => rdpSummary(d), user: (d) => v(d, 'User') },
      22: { label: 'RDP shell start', category: 'rdp', summary: (d) => rdpSummary(d), user: (d) => v(d, 'User') },
      23: { label: 'RDP logoff', category: 'rdp', summary: (d) => rdpSummary(d), user: (d) => v(d, 'User') },
      24: { label: 'RDP disconnected', category: 'rdp', summary: (d) => rdpSummary(d), user: (d) => v(d, 'User') },
      25: { label: 'RDP reconnected', category: 'rdp', summary: (d) => rdpSummary(d), user: (d) => v(d, 'User') },
    },
  },
  {
    key: 'microsoft-windows-terminalservices-remoteconnectionmanager/operational',
    name: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
    short: 'RDP auth',
    file: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx',
    events: {
      1149: {
        label: 'RDP authentication',
        category: 'rdp',
        summary: (d) => `${v(d, 'Param1')} ${v(d, 'Param2')} from ${v(d, 'Param3') || '?'}`.trim(),
        user: (d) => v(d, 'Param1'),
      },
    },
  },
  {
    key: 'microsoft-windows-windows defender/operational',
    name: 'Microsoft-Windows-Windows Defender/Operational',
    short: 'Defender',
    file: 'Microsoft-Windows-Windows Defender%4Operational.evtx',
    events: {
      1116: {
        label: 'Malware detected',
        category: 'defender',
        summary: (d) => `${v(d, 'Threat Name', 'ThreatName')} — ${short(v(d, 'Path'))}`,
        user: (d) => v(d, 'Detection User'),
      },
      1117: {
        label: 'Malware action taken',
        category: 'defender',
        summary: (d) => `${v(d, 'Threat Name', 'ThreatName')}: ${v(d, 'Action Name')}`,
        user: (d) => v(d, 'Detection User'),
      },
      5001: { label: 'Real-time protection disabled', category: 'defender', summary: () => 'real-time protection off' },
    },
  },
  {
    key: 'microsoft-windows-taskscheduler/operational',
    name: 'Microsoft-Windows-TaskScheduler/Operational',
    short: 'Task Scheduler',
    file: 'Microsoft-Windows-TaskScheduler%4Operational.evtx',
    events: {
      106: {
        label: 'Task registered',
        category: 'task',
        summary: (d) => v(d, 'TaskName'),
        user: (d) => v(d, 'UserContext'),
      },
      141: {
        label: 'Task deleted',
        category: 'task',
        summary: (d) => v(d, 'TaskName'),
        user: (d) => v(d, 'UserName'),
      },
      200: {
        label: 'Task action started',
        category: 'task',
        summary: (d) => `${v(d, 'TaskName')} → ${short(v(d, 'ActionName'))}`,
      },
    },
  },
  {
    key: 'microsoft-windows-sysmon/operational',
    name: 'Microsoft-Windows-Sysmon/Operational',
    short: 'Sysmon',
    file: 'Microsoft-Windows-Sysmon%4Operational.evtx',
    events: {
      1: {
        label: 'Process created',
        category: 'process',
        summary: (d) => short(v(d, 'CommandLine', 'Image')),
        user: (d) => v(d, 'User'),
      },
      3: {
        label: 'Network connection',
        category: 'network',
        summary: (d) =>
          `${base(v(d, 'Image'))} → ${v(d, 'DestinationHostname') || v(d, 'DestinationIp')}:${v(d, 'DestinationPort')}`,
        user: (d) => v(d, 'User'),
      },
      22: {
        label: 'DNS query',
        category: 'network',
        summary: (d) => `${base(v(d, 'Image'))} → ${v(d, 'QueryName')}`,
        user: (d) => v(d, 'User'),
      },
    },
  },
]

function hostApplication(d) {
  const text = v(d, 'Data3', 'Data2')
  const match = /HostApplication=([^\n]*)/.exec(text)
  return match ? match[1] : text
}

function rdpSummary(d) {
  const address = v(d, 'Address')
  return `${v(d, 'User') || '?'}${address && address !== 'LOCAL' ? ` from ${address}` : ''}`
}

function base(path) {
  return String(path ?? '')
    .split(/[\\/]/)
    .pop()
}

const BY_KEY = new Map(EVENT_CHANNELS.map((channel) => [channel.key, channel]))

/** A channel definition from any spelling of its name, or null. */
export function getChannel(name) {
  return BY_KEY.get(String(name ?? '').toLowerCase()) ?? null
}

/** The catalog entry of an event id in a channel, or null when not curated. */
export function getEventDefinition(channelName, eventId) {
  return getChannel(channelName)?.events[eventId] ?? null
}

/** `{ channelKey: [ids] }` — the curated set (mirrored on the server). */
export const CURATED_EVENTS = Object.fromEntries(
  EVENT_CHANNELS.map((channel) => [channel.key, Object.keys(channel.events).map(Number)]),
)

/*
 * Collection script: exports the curated events of every channel above as
 * JSON (native Get-WinEvent, no third-party tool). Run it elevated: the
 * Security log needs administrator rights. FilterHashtable takes at most 23
 * ids at a time, so ids are queried in batches.
 */
export const EVENTLOG_COLLECTION_SCRIPT = {
  lang: 'powershell',
  code: String.raw`
# Nik — curated Windows event logs → nik-eventlogs.json (run as administrator)
$curated = [ordered]@{
${EVENT_CHANNELS.map((c) => `  '${c.name}' = @(${Object.keys(c.events).join(',')})`).join('\n')}
}
$logs = @(); $events = [System.Collections.Generic.List[object]]::new()
foreach ($name in $curated.Keys) {
  $info = Get-WinEvent -ListLog $name -ErrorAction SilentlyContinue
  if (-not $info) { continue }
  $oldest = Get-WinEvent -LogName $name -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
  $newest = Get-WinEvent -LogName $name -MaxEvents 1 -ErrorAction SilentlyContinue
  $logs += [pscustomobject]@{
    name  = $name
    total = $info.RecordCount
    first = if ($oldest) { $oldest.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
    last  = if ($newest) { $newest.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
  }
  $ids = $curated[$name]
  for ($i = 0; $i -lt $ids.Count; $i += 20) {
    $batch = $ids[$i..([Math]::Min($i + 19, $ids.Count - 1))]
    Get-WinEvent -FilterHashtable @{ LogName = $name; Id = $batch } -ErrorAction SilentlyContinue | ForEach-Object {
      $xml = [xml]$_.ToXml(); $data = [ordered]@{}; $n = 0
      foreach ($d in $xml.Event.EventData.Data) {
        $n++; $key = if ($d.Name) { $d.Name } else { "Data$n" }; $data[$key] = $d.'#text'
      }
      if ($xml.Event.UserData) {
        foreach ($f in $xml.Event.UserData.FirstChild.ChildNodes) { $data[$f.LocalName] = $f.InnerText }
      }
      $events.Add([pscustomobject]@{
        TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
        Id = $_.Id; LogName = $_.LogName; ProviderName = $_.ProviderName
        RecordId = $_.RecordId; MachineName = $_.MachineName; Level = $_.Level; Data = $data
      })
    }
  }
}
[pscustomobject]@{ format = 'nik-eventlogs'; host = $env:COMPUTERNAME; logs = $logs; events = $events } |
  ConvertTo-Json -Depth 5 -Compress | Out-File -Encoding utf8 .\nik-eventlogs.json
`.trim(),
}
