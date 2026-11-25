import assert from 'node:assert/strict'
import { test } from 'node:test'
import { getBrowserById } from '../config/browsers.js'
import {
  addressOf,
  domainStat,
  needsReread,
  dataFilterOf,
  fromOf,
  pickedFilters,
  scopeFilters,
  sourceChoices,
  browserItems,
  countText,
  expectedFor,
  inScope,
  matchFor,
  profileItems,
  profileNameError,
  profileNames,
  resolveProfileName,
  scopedSources,
  sectionCount,
  sourceForFile,
  summaryText,
  typeTotals,
} from './browserEvidence.js'

const file = (id, source, profile, extra = {}) => ({
  id,
  kind: 'browser',
  source,
  profile,
  state: 'done',
  read: 'complete',
  kept: 5,
  fileName: source,
  ...extra,
})

const SOURCES = [
  file('a', 'chrome.history', 'Default', { kept: 8, read: 'partial' }),
  file('b', 'chrome.bookmarks', 'Default', { kept: 3 }),
  file('c', 'chrome.history', 'Profile 1', { kept: 4, read: 'partial', seen: { by: 'x' } }),
  file('d', 'edge.history', '', { kept: 2 }),
  { id: 'e', kind: 'eventlog', source: 'evtx', kept: 99 },
]

test('browser tabs count the records kept and mark a file read in part that nobody looked at', () => {
  const items = browserItems(SOURCES)
  assert.equal(items.length, 6)
  const chrome = items.find((item) => item.id === 'chrome')
  assert.deepEqual([chrome.count, chrome.partial], [15, true])
  const edge = items.find((item) => item.id === 'edge')
  assert.deepEqual([edge.count, edge.partial], [2, false])
  assert.equal(items.find((item) => item.id === 'firefox').count, 0)
})

test('profiles come from the files, an empty one is Default, Default is first', () => {
  assert.deepEqual(profileNames(SOURCES, 'chrome'), ['Default', 'Profile 1'])
  assert.deepEqual(profileNames(SOURCES, 'edge'), ['Default'])
  assert.deepEqual(profileNames(SOURCES, 'firefox'), ['Default'])
  assert.deepEqual(profileNames(SOURCES, 'chrome', ['Work', 'Default']), ['Default', 'Profile 1', 'Work'])
})

test('profile tabs carry their counts', () => {
  const items = profileItems(SOURCES, 'chrome')
  assert.deepEqual(
    items.map((item) => [item.id, item.count, item.partial]),
    [
      ['Default', 11, true],
      ['Profile 1', 4, false],
    ],
  )
  assert.equal(profileItems(SOURCES, 'chrome', ['Work']).length, 3)
})

test('a file is in a scope by its browser and its profile, an empty profile being Default', () => {
  assert.equal(inScope(SOURCES[3], 'edge', 'Default'), true)
  assert.equal(inScope(SOURCES[3], 'edge', 'Profile 1'), false)
  assert.equal(inScope(SOURCES[3], 'chrome', 'Default'), false)
  assert.equal(inScope(SOURCES[4], 'chrome', 'Default'), false)
})

test('a profile name is checked and an existing one is chosen in any case', () => {
  assert.equal(profileNameError('  '), 'Enter a profile name.')
  assert.match(profileNameError('x'.repeat(121)), /at most 120/)
  assert.equal(profileNameError('Profile 2'), null)
  assert.equal(resolveProfileName(['Default', 'Work'], ' work '), 'Work')
  assert.equal(resolveProfileName(['Default'], ' New '), 'New')
})

test('the scope of a table, a stat or a stack is the browser prefix and the profile', () => {
  assert.deepEqual(scopeFilters('chrome', 'Profile 1'), {
    kind: 'browser',
    sourcePrefix: 'chrome.',
    profile: 'Profile 1',
  })
  assert.deepEqual(
    scopedSources(SOURCES, 'chrome', 'Default').map((source) => source.id),
    ['a', 'b'],
  )
})

test('totals per type are summed over files and give the count of a section', () => {
  const totals = typeTotals([
    {
      values: [
        { value: 'visit', count: 7 },
        { value: 'download', count: 1 },
      ],
    },
    {
      values: [
        { value: 'visit', count: 3 },
        { value: 'bookmark', count: 2 },
      ],
    },
    null,
  ])
  assert.deepEqual(totals, { visit: 10, download: 1, bookmark: 2 })
  assert.equal(sectionCount(totals, 'events'), 11)
  assert.equal(sectionCount(totals, 'bookmarks'), 2)
  assert.equal(sectionCount(totals, 'shortcuts'), 0)
})

test('the domains stat is the distinct of the stack', () => {
  assert.deepEqual(domainStat({ distinct: 4, missing: 1 }), { count: 4, capped: false })
  assert.equal(domainStat({ distinct: 5000, distinctCapped: true, missing: 0 }).capped, true)
  assert.deepEqual(domainStat(undefined), { count: 0, capped: false })
  assert.equal(countText(1234, true), '1,234+')
  assert.equal(countText(4), '4')
})

test('a file must be read again for its domains only when the parser is older than 2, or it is legacy', () => {
  assert.equal(needsReread([{ parser: 'browser', parserVersion: '2' }]), false)
  assert.equal(needsReread([{ parser: 'browser', parserVersion: '1' }]), true)
  assert.equal(needsReread([{ parser: 'browser', parserVersion: '10' }]), false)
  assert.equal(needsReread([{ parser: 'history', parserVersion: '1' }]), false)
  assert.equal(needsReread([{ legacy: true }]), true)
  assert.equal(
    needsReread([
      { parser: 'browser', parserVersion: '2' },
      { parser: 'browser', parserVersion: '1' },
    ]),
    true,
  )
  assert.equal(needsReread([]), false)
})

test('a value picked in a stack is a filter on its data key, other fields are filters by name', () => {
  assert.deepEqual(pickedFilters('data.domain', 'example.net'), { dataKey: 'domain', dataValue: 'example.net' })
  assert.deepEqual(pickedFilters('type', 'visit'), { type: 'visit' })
  assert.deepEqual(dataFilterOf({ dataKey: 'domain', dataValue: 'a.b' }), { key: 'domain', value: 'a.b' })
  assert.equal(dataFilterOf({}), null)
})

test('a file the page cannot place is one of the sources of the browser, and a download says where from', () => {
  assert.deepEqual(
    sourceChoices(getBrowserById('chrome')).map((choice) => choice.value),
    ['chrome.history', 'chrome.bookmarks', 'chrome.shortcuts'],
  )
  assert.equal(fromOf({ referrerDomain: 'a.org', domain: 'b.org' }), 'a.org')
  assert.equal(fromOf({ domain: 'b.org' }), 'b.org')
  assert.equal(fromOf(undefined), '')
})

test('the expected files are those of the browser, with where to find them', () => {
  const chrome = expectedFor(getBrowserById('chrome'), 'windows')
  assert.deepEqual(
    chrome.map((item) => item.key),
    ['history', 'bookmarks', 'shortcuts'],
  )
  assert.match(chrome[0].hint, /^%LOCALAPPDATA%\\Google\\Chrome\\User Data\\<profile>\\History: /)
  const match = matchFor('chrome')
  assert.equal(match(SOURCES[0]), 'history')
  assert.equal(match(SOURCES[3]), null)
  assert.equal(match(SOURCES[4]), null)
})

test('a file is told what it is of its browser by its name', () => {
  assert.equal(sourceForFile('edge', 'History'), 'edge.history')
  assert.equal(sourceForFile('edge', 'C:\\x\\Bookmarks'), 'edge.bookmarks')
  assert.equal(sourceForFile('brave', 'shortcuts'), 'brave.shortcuts')
  assert.equal(sourceForFile('opera', 'export.json'), 'opera.json')
  assert.equal(sourceForFile('opera', 'export.CSV'), 'opera.csv')
  assert.equal(sourceForFile('chrome', 'copy of something'), '')
  assert.equal(sourceForFile('firefox', 'places.sqlite'), 'firefox.places')
  assert.equal(sourceForFile('firefox', 'anything'), 'firefox.places')
  assert.equal(sourceForFile('safari', 'History.db'), 'safari.history')
  assert.equal(sourceForFile('safari', 'Downloads.plist'), 'safari.downloads')
  assert.equal(sourceForFile('safari', 'Bookmarks.plist'), 'safari.bookmarks')
  assert.equal(sourceForFile('safari', 'other'), '')
  assert.equal(sourceForFile('nobody', 'History'), '')
})

test('addresses are defanged in the summary, titles are not', () => {
  assert.equal(
    summaryText({ type: 'visit', summary: 'https://pay.example.net/login' }),
    'hxxps[:]//pay[.]example[.]net/login',
  )
  assert.equal(summaryText({ type: 'visit', summary: 'Payroll portal. Log in' }), 'Payroll portal. Log in')
  assert.equal(
    summaryText({ type: 'download', summary: 'Payslip_Nov.docm <- pay.example.net' }),
    'Payslip_Nov.docm <- pay[.]example[.]net',
  )
  assert.equal(summaryText({ type: 'download', summary: 'file.zip' }), 'file.zip')
  assert.equal(summaryText({ type: 'search', summary: 'november payslip' }), 'november payslip')
  assert.equal(summaryText(null), '')
})

test('the address of a record is its url, or nothing', () => {
  assert.equal(addressOf({ url: 'https://a.example/' }), 'https://a.example/')
  assert.equal(addressOf({ url: '' }), '')
  assert.equal(addressOf({ url: 4 }), '')
  assert.equal(addressOf(undefined), '')
})
