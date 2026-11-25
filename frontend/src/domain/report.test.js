import test from 'node:test'
import assert from 'node:assert/strict'
import { REPORT_SECTIONS, reportSettings } from './report.js'

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
