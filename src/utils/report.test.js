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

test('reportSettings fills the defaults', () => {
  assert.deepEqual(reportSettings({}), {
    lang: 'en',
    tlp: 'amber',
    sections: REPORT_SECTIONS.map((s) => s.id),
    executiveSummary: '',
  })
  assert.equal(reportSettings({ report: { lang: 'it', tlp: 'bogus' } }).tlp, 'amber')
  assert.equal(reportSettings({ report: { lang: 'it' } }).lang, 'it')
})
