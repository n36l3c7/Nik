import test from 'node:test'
import assert from 'node:assert/strict'
import { REPORT_SECTIONS, reportDetections, reportSettings } from './report.js'

test('reportDetections counts each rule once per event, with its ATT&CK ids', () => {
  const cleared = { id: 'evt-log-cleared', label: 'log cleared', severity: 'high', attack: ['T1070.001'] }
  const keyword = { id: 'pastebin', label: 'pastebin', severity: 'medium' }
  const events = [
    { soc: { keywordMatches: [cleared] } },
    { soc: { keywordMatches: [cleared, keyword] } },
    { soc: { keywordMatches: [] } },
  ]
  assert.deepEqual(reportDetections(events), [
    { id: 'evt-log-cleared', label: 'log cleared', severity: 'high', count: 2, attack: ['T1070.001'] },
    { id: 'pastebin', label: 'pastebin', severity: 'medium', count: 1, attack: [] },
  ])
})

test('with the flags, only the hits on flagged events count', () => {
  const rule = { id: 'r1', label: 'download and run', severity: 'high', attack: ['T1105'] }
  const events = [
    { id: 'e1', soc: { keywordMatches: [rule] } },
    { id: 'e2', soc: { keywordMatches: [rule] } },
    { id: 'e3', flaggable: { key: 'sample:abc' }, soc: { keywordMatches: [rule] } },
  ]
  assert.equal(reportDetections(events)[0].count, 3)
  assert.equal(reportDetections(events, { e2: {}, 'sample:abc': {} })[0].count, 2)
  assert.deepEqual(reportDetections(events, {}), [])
})

test('reportSettings fills the defaults', () => {
  assert.deepEqual(reportSettings({}), {
    lang: 'en',
    tlp: 'amber',
    sections: REPORT_SECTIONS.map((s) => s.id),
    executiveSummary: '',
    scope: 'flagged',
  })
  assert.equal(reportSettings({ report: { scope: 'all' } }).scope, 'all')
  assert.equal(reportSettings({ report: { scope: 'bogus' } }).scope, 'flagged')
  assert.equal(reportSettings({ report: { lang: 'it', tlp: 'bogus' } }).tlp, 'amber')
  assert.equal(reportSettings({ report: { lang: 'it' } }).lang, 'it')
})
