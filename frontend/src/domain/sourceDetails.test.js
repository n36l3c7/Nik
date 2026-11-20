import test from 'node:test'
import assert from 'node:assert/strict'
import {
  abuseReports,
  commandOf,
  cutNote,
  genericFacts,
  networkRange,
  otxPulses,
  otxValidation,
  safeBrowsingMatches,
  sourceOf,
  threatfoxIocs,
  toMs,
  urlhausPayloads,
  urlhausUrls,
  urlscanScans,
  vtEngines,
  youngDomainDays,
} from './sourceDetails.js'

test('an answer names the connector and the command that gave it', () => {
  assert.equal(sourceOf({ _command: 'virustotal.get-ip-report' }), 'virustotal')
  assert.equal(commandOf({ _command: 'virustotal.get-ip-report' }), 'get-ip-report')
  assert.equal(sourceOf({}), '')
  assert.equal(sourceOf(null), '')
  assert.equal(commandOf({ _command: 42 }), '')
})

test('the dates of the vendors become one kind of number', () => {
  const at = Date.UTC(2026, 0, 31, 10, 0, 0)
  assert.equal(toMs('2026-01-31T10:00:00Z'), at)
  assert.equal(toMs('2026-01-31T10:00:00+00:00'), at)
  assert.equal(toMs('2026-01-31 10:00:00 UTC'), at)
  assert.equal(toMs('2026-01-31 10:00:00'), at) // abuse.ch without its "UTC" is UTC all the same
  assert.equal(toMs('2026-01-31T10:00:00'), at)
  assert.equal(toMs(at / 1000), at) // seconds
  assert.equal(toMs(at), at) // milliseconds
  for (const nothing of [null, undefined, '', 'soon', 0, {}, NaN]) assert.equal(toMs(nothing), null)
})

test('AbuseIPDB reports: ten at most, categories by name, comments cut', () => {
  const raw = Array.from({ length: 14 }, (_, n) => ({
    reportedAt: '2026-01-31T10:00:00+00:00',
    categories: [18, 22, 999],
    comment: 'x'.repeat(500),
    reporterCountryCode: n === 0 ? 'DE' : 'US',
  }))
  const shown = abuseReports(raw)
  assert.equal(shown.length, 10)
  assert.deepEqual(shown[0].categories, ['Brute-Force', 'SSH', '999'])
  assert.equal(shown[0].comment.length, 300)
  assert.equal(shown[0].country, 'DE')
  assert.equal(shown[0].date, Date.UTC(2026, 0, 31, 10))
  assert.deepEqual(abuseReports(undefined), [])
  assert.deepEqual(abuseReports('no'), [])
})

test('VirusTotal vendors: those that flag it, or all of them when asked and given', () => {
  const data = {
    engines: [{ engine: 'Kaspersky', category: 'malicious', result: 'Trojan' }],
    all_engines: [
      { engine: 'Kaspersky', category: 'malicious', result: 'Trojan' },
      { engine: 'Avira', category: 'harmless', result: 'clean' },
      { nothing: true },
    ],
  }
  assert.deepEqual(vtEngines(data), [{ engine: 'Kaspersky', category: 'malicious', result: 'Trojan' }])
  assert.deepEqual(
    vtEngines(data, true).map((row) => row.engine),
    ['Kaspersky', 'Avira'],
  )
  assert.deepEqual(vtEngines({ engines: data.engines }, true).length, 1) // an answer without the full list
  assert.deepEqual(vtEngines({}), [])
})

test('OTX pulses link to their page; what vouches for a value is read from either field', () => {
  const [pulse] = otxPulses([
    { id: 'abc', name: 'Tor exits', author: 'alice', modified: '2026-01-31T10:00:00', tags: 'abcdefgh'.split('') },
  ])
  assert.equal(pulse.link, 'https://otx.alienvault.com/pulse/abc')
  assert.equal(pulse.tags.length, 6)
  assert.equal(pulse.modified, Date.UTC(2026, 0, 31, 10))
  assert.equal(otxPulses([{ name: 'No id' }])[0].link, '')
  assert.deepEqual(otxValidation([{ message: 'Whitelisted domain' }, { name: 'akamai' }, {}, null]), [
    'Whitelisted domain',
    'akamai',
  ])
})

test('abuse.ch: ThreatFox indicators, URLhaus payloads and URLs', () => {
  const [ioc] = threatfoxIocs([
    {
      id: '41',
      ioc: '203.0.113.7:443',
      threat_type: 'botnet_cc',
      threat_type_desc: 'Botnet C2',
      malware_printable: 'Cobalt Strike',
      confidence_level: 100,
      first_seen: '2026-01-31 10:00:00 UTC',
    },
  ])
  assert.deepEqual(ioc, {
    ioc: '203.0.113.7:443',
    threat: 'Botnet C2',
    malware: 'Cobalt Strike',
    confidence: 100,
    firstSeen: Date.UTC(2026, 0, 31, 10),
    link: 'https://threatfox.abuse.ch/ioc/41/',
  })
  assert.equal(threatfoxIocs(Array(30).fill({ ioc: 'x' })).length, 10)
  assert.deepEqual(
    urlhausPayloads([{ response_sha256: 'aa', file_type: 'exe', signature: null, firstseen: '2026-01-31' }]),
    [{ sha256: 'aa', fileType: 'exe', signature: null, firstSeen: Date.UTC(2026, 0, 31) }],
  )
  const [url] = urlhausUrls([
    {
      url: 'http://evil.example/x',
      url_status: 'online',
      threat: 'malware_download',
      date_added: '2026-01-31 10:00:00 UTC',
    },
  ])
  assert.deepEqual(url, {
    url: 'http://evil.example/x',
    status: 'online',
    threat: 'malware_download',
    added: Date.UTC(2026, 0, 31, 10),
  })
})

test('urlscan scans read the verdict in either shape; Safe Browsing matches in plain words', () => {
  const scans = urlscanScans([
    {
      _id: 's1',
      task: { time: '2026-01-31T10:00:00.000Z' },
      page: { url: 'http://a/', ip: '203.0.113.7' },
      verdicts: { malicious: true },
    },
    { _id: 's2', page: {}, verdicts: { overall: { malicious: true } } },
    { page: { title: 'Fine' } },
  ])
  assert.deepEqual(
    scans.map((scan) => scan.malicious),
    [true, true, false],
  )
  assert.equal(scans[0].result, 'https://urlscan.io/result/s1/')
  assert.equal(scans[2].result, '')
  assert.deepEqual(
    safeBrowsingMatches([
      { threatType: 'SOCIAL_ENGINEERING', platformType: 'ANY_PLATFORM', threat: { url: 'http://a/' } },
    ]),
    [{ threat: 'social engineering', platform: 'any platform', url: 'http://a/' }],
  )
})

test('a network is its CIDRs, or its first and last address', () => {
  assert.equal(networkRange({ cidrs: [{ v4prefix: '203.0.113.0', length: 24 }] }), '203.0.113.0/24')
  assert.equal(
    networkRange({ start_address: '203.0.113.0', end_address: '203.0.113.255' }),
    '203.0.113.0 – 203.0.113.255',
  )
  assert.equal(networkRange({}), null)
})

test('a young domain is one a registry flags, with its age', () => {
  const rdap = { provider: 'rdap', status: 'done', verdict: 'suspicious', data: { age_days: 3 } }
  assert.equal(youngDomainDays([{ provider: 'virustotal', status: 'done', verdict: 'malicious', data: {} }, rdap]), 3)
  assert.equal(youngDomainDays([{ ...rdap, verdict: 'unknown', data: { age_days: 4000 } }]), null)
  assert.equal(youngDomainDays([{ ...rdap, status: 'error' }]), null)
  assert.equal(youngDomainDays(undefined), null)
})

test('an answer without a layout of its own is shown as plain rows', () => {
  const rows = genericFacts({
    _command: 'rated.check-ip',
    _instance: 'Rated',
    hits: 4,
    listed: true,
    first_seen: '2026-01-31',
    tags: ['c2', 'tor'],
    reports: [{ a: 1 }, { a: 2 }],
    nested: { deep: true },
    nothing: null,
    empty: [],
  })
  assert.deepEqual(rows, [
    ['hits', '4'],
    ['listed', 'yes'],
    ['first seen', '2026-01-31'],
    ['tags', 'c2, tor'],
    ['reports', '2 entries'],
  ])
  assert.deepEqual(genericFacts(null), [])
})

test('a list the server cut is said, once', () => {
  assert.equal(cutNote({}), '')
  assert.equal(
    cutNote({ _cut: { reports: 2400, all_engines: 120 } }),
    'Longer than the page shows, whole in the JSON download: reports (2400), all engines (120).',
  )
})
