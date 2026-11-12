import test from 'node:test'
import assert from 'node:assert/strict'
import {
  DEFAULT_EXPORT_FIELDS,
  cleanExportFields,
  durationLabel,
  isIndicatorList,
  isSeveralValues,
  libraryPath,
  libraryQuery,
  mayHoldIndicators,
  scopeFilters,
  sourceLine,
  verdictRowClass,
  viewFromPath,
} from './iocLibrary.js'

test('each view of the library has an address', () => {
  assert.equal(libraryPath({ kind: 'all' }), '/iocs')
  assert.equal(libraryPath({ kind: 'list', id: 'a b' }), '/iocs/lists/a%20b')
  assert.equal(libraryPath({ kind: 'alerts' }), '/iocs/alerts')
  assert.deepEqual(viewFromPath('/iocs/'), { kind: 'all' })
  assert.deepEqual(viewFromPath('/iocs/lists/a%20b'), { kind: 'list', id: 'a b' })
  assert.deepEqual(viewFromPath('/iocs/alerts'), { kind: 'alerts' })
  // An indicator's own page (/ioc/<type>) is not the library.
  assert.equal(viewFromPath('/ioc/ip'), null)
  assert.equal(viewFromPath('/incident/x'), null)
})

test('filters become the query and the scope without empty values', () => {
  const filters = { q: ' evil ', type: 'ip', verdict: '', origin: '', expired: false }
  assert.equal(
    libraryQuery({ filters, list: 'L1', sort: { key: 'score', dir: 'desc' }, offset: 100 }),
    'q=evil&type=ip&expired=false&list=L1&sort=score&dir=desc&offset=100&limit=100',
  )
  assert.deepEqual(scopeFilters(filters, 'L1'), { q: 'evil', type: 'ip', expired: false, list: 'L1' })
  assert.deepEqual(scopeFilters({}), {})
})

test('a row is tinted by its verdict only', () => {
  assert.match(verdictRowClass('malicious'), /high/)
  assert.match(verdictRowClass('suspicious'), /med-soft/)
  assert.equal(verdictRowClass('harmless'), '')
  assert.equal(verdictRowClass(null), '')
})

test('the stored choice of export fields is cleaned', () => {
  assert.deepEqual(cleanExportFields(null), DEFAULT_EXPORT_FIELDS)
  assert.deepEqual(cleanExportFields(['note', 'bogus', 'value']), ['value', 'note'])
  assert.deepEqual(cleanExportFields([]), DEFAULT_EXPORT_FIELDS)
})

test('a dropped file is read as indicators only when it can be one', () => {
  assert.equal(mayHoldIndicators({ name: 'iocs.txt', size: 200, route: null }), true)
  assert.equal(mayHoldIndicators({ name: 'feed.csv', size: 200, route: { tab: 'endpoint' } }), true)
  assert.equal(mayHoldIndicators({ name: 'a.exe', size: 200, route: { tab: 'malware' } }), false)
  assert.equal(mayHoldIndicators({ name: 'big.txt', size: 9_000_000, route: null }), false)
  assert.equal(mayHoldIndicators({ name: 'photo.png', size: 200, route: null }), false)
})

test('plain text is a list of indicators when most lines hold one', () => {
  assert.equal(isIndicatorList({ format: 'stix', items: [{}] }), true)
  assert.equal(isIndicatorList({ format: 'text', items: [] }, 'a\nb'), false)
  assert.equal(isIndicatorList({ format: 'csv', items: [{}, {}] }, 'type,value\nip,1.2.3.4\ndomain,evil.example'), true)
  assert.equal(isIndicatorList({ format: 'csv', items: [{}] }, 'name,value\na,1\nb,2\nc,evil.example\nd,4'), false)
  assert.equal(isIndicatorList({ format: 'text', items: [{}, {}] }, '1.2.3.4\nevil.example\n# note'), true)
  assert.equal(
    isIndicatorList({ format: 'text', items: [{}] }, 'log line\nlog line\nGET http://x.example/\nmore'),
    false,
  )
})

test('several pasted values are told from one', () => {
  assert.equal(isSeveralValues('1.2.3.4'), false)
  assert.equal(isSeveralValues('1.2.3.4\nevil.example'), true)
  assert.equal(isSeveralValues('1.2.3.4, evil.example'), true)
})

test('a bulk check is described in plain words', () => {
  assert.equal(durationLabel(20), '< 1 min')
  assert.equal(durationLabel(1440), '24 min')
  assert.equal(durationLabel(5400), '1.5 h')
  assert.equal(sourceLine({ needed: 5, leftToday: null }), '5 · no daily limit')
  assert.equal(sourceLine({ needed: 120, leftToday: 74, today: 74, later: 46 }), '74 today, 46 wait for the quota')
  assert.equal(sourceLine({ needed: 88, leftToday: 941, today: 88, later: 0 }), '88 of 941 left today')
})
