import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  actionBadge,
  byKind,
  choicesOf,
  diffLines,
  idFromName,
  importable,
  initialSkips,
  packProblem,
  planSummary,
  plural,
} from './packs.js'

const PLAN = {
  problems: [],
  counts: { add: 1, update: 1, same: 1, conflict: 1 },
  items: [
    { kind: 'fields', name: 'customer', label: 'Field', action: 'conflict', why: 'another type' },
    { kind: 'scripts', name: 'CountWords', label: 'Script', action: 'update', diff: '…' },
    { kind: 'lists', name: 'vip_users', label: 'List', action: 'add' },
    { kind: 'dashboards', name: 'Cases', label: 'Dashboard', action: 'same' },
  ],
}

test('the plan of an import: what it says, what starts left out, whether it can be applied', () => {
  assert.equal(planSummary(PLAN.counts), '1 to add, 1 to update, 1 the same, 1 in conflict')
  assert.equal(planSummary({}), 'It holds nothing')
  assert.equal(actionBadge('conflict').color, 'red')
  assert.equal(actionBadge('other').label, 'other')
  // A conflict starts left out, so the rest can be applied at once.
  const skipped = initialSkips(PLAN)
  assert.deepEqual([...skipped], ['fields/customer'])
  assert.deepEqual(importable(PLAN, skipped), { ok: true, why: '', changes: 2 })
  assert.deepEqual(choicesOf(skipped), { 'fields/customer': 'skip' })
  // Put back, it stops everything, and the reason names it.
  const blocked = importable(PLAN, new Set())
  assert.equal(blocked.ok, false)
  assert.match(blocked.why, /Field "customer" conflicts/)
  // What the pack requires and is not there stops it whatever is skipped.
  assert.equal(
    importable({ ...PLAN, problems: ['It requires the pack "base"'] }, skipped).why,
    'It requires the pack "base"',
  )
  const all = new Set(PLAN.items.map((item) => `${item.kind}/${item.name}`))
  assert.equal(importable(PLAN, all).why, 'Everything is left out')
  assert.equal(importable(null, new Set()).ok, false)
})

test('a difference as lines, without its two headers', () => {
  const diff = '--- here\n+++ in the pack\n@@ -1,2 +1,2 @@\n name: x\n-code: old\n+code: new'
  assert.deepEqual(diffLines(diff), [
    { kind: 'hunk', text: '@@ -1,2 +1,2 @@' },
    { kind: 'same', text: ' name: x' },
    { kind: 'del', text: '-code: old' },
    { kind: 'add', text: '+code: new' },
  ])
  assert.deepEqual(diffLines(''), [{ kind: 'same', text: '' }])
})

test('the identity of a pack that is being made', () => {
  assert.equal(idFromName('Acme SOC!'), 'acme-soc')
  assert.equal(idFromName('2026 rules'), 'pack-2026-rules')
  assert.equal(idFromName('???'), '')
  assert.equal(packProblem({ id: 'acme-soc', name: 'Acme SOC', version: '1.0.0' }), null)
  assert.match(packProblem({ id: 'acme-soc', name: ' ', version: '1.0.0' }), /needs a name/)
  assert.match(packProblem({ id: 'Acme', name: 'Acme', version: '1.0.0' }), /lower-case letter/)
  assert.match(packProblem({ id: 'acme', name: 'Acme', version: '1.0' }), /three numbers/)
  assert.match(packProblem({ id: 'acme', name: 'Acme', version: '1.0.0' }, 0), /one item/)
})

test('items by kind, and a pack in a line', () => {
  const groups = byKind(PLAN.items)
  assert.deepEqual(
    groups.map((group) => [group.kind, group.label, group.items.length]),
    [
      ['fields', 'Field', 1],
      ['scripts', 'Script', 1],
      ['lists', 'List', 1],
      ['dashboards', 'Dashboard', 1],
    ],
  )
  assert.equal(plural('Incident type', 2), 'Incident types')
  assert.equal(plural('Field', 1), 'Field')
})

test('the catalogue and what is installed make one list of cards', async () => {
  const { byVendor, cardCounts, contentsLine, contentsOf, filterCards, packCards, uninstallCounts } =
    await import('./packs.js')
  const catalogue = {
    packs: [
      {
        id: 'jira-cloud',
        name: 'Jira Cloud',
        vendor: 'Atlassian',
        category: 'Ticketing',
        version: '1.3.0',
        installed: '1.2.0',
        update: true,
        needsNik: '',
        contents: { connectors: 1, commands: 41, mappers: 1 },
        logo: { type: 'image/png' },
      },
      { id: 'zscaler-zia', name: 'Zscaler Internet Access', vendor: 'Zscaler', version: '1.0.0', needsNik: '' },
      { id: 'urlscan', name: 'urlscan.io', vendor: '', version: '1.0.0', needsNik: '6.1', premium: 2 },
      { id: 'confluence-cloud', name: 'Confluence Cloud', vendor: 'Atlassian', version: '1.0.0', installed: '1.0.0' },
    ],
  }
  const installed = [
    { id: 'nik', name: 'Nik built-in', version: '6.0.0', builtin: true, items: [{ kind: 'scripts', name: 'A' }] },
    { id: 'jira-cloud', name: 'Jira Cloud', version: '1.2.0', vendor: 'Atlassian', hasLogo: true, items: [] },
    { id: 'confluence-cloud', name: 'Confluence Cloud', version: '1.0.0', vendor: 'Atlassian', items: [] },
    { id: 'ours', name: 'Ours', version: '0.1.0', vendor: '', source: 'file', items: [{ kind: 'lists', name: 'x' }] },
  ]
  const cards = packCards(catalogue, installed)
  const state = Object.fromEntries(cards.map((card) => [card.id, card.state]))
  assert.deepEqual(state, {
    'jira-cloud': 'update',
    'zscaler-zia': 'available',
    urlscan: 'later',
    'confluence-cloud': 'installed',
    nik: 'installed',
    ours: 'installed',
  })
  assert.deepEqual(cardCounts(cards), { all: 6, installed: 4, updates: 1 })
  const jira = cards.find((card) => card.id === 'jira-cloud')
  assert.equal(jira.logo, 'catalogue')
  assert.equal(jira.installed, '1.2.0')
  assert.equal(cards.find((card) => card.id === 'ours').inCatalogue, false)
  // Nik first, the vendors by name, what names no vendor last.
  assert.deepEqual(
    byVendor(cards).map((group) => [group.vendor, group.cards.map((card) => card.id)]),
    [
      ['Nik', ['nik']],
      ['Atlassian', ['confluence-cloud', 'jira-cloud']],
      ['Zscaler', ['zscaler-zia']],
      ['Other', ['ours', 'urlscan']],
    ],
  )
  assert.deepEqual(
    filterCards(cards, 'installed', 'atlas').map((card) => card.id),
    ['jira-cloud', 'confluence-cloud'],
  )
  assert.deepEqual(
    filterCards(cards, 'updates').map((card) => card.id),
    ['jira-cloud'],
  )
  assert.equal(filterCards(cards, 'all', 'ticketing').length, 1)
  assert.equal(
    contentsLine({ connectors: 1, commands: 41, mappers: 1, playbooks: 2 }, 3),
    'connector (41 commands, 3 premium) · 2 playbooks · 1 mapper',
  )
  assert.equal(contentsLine({ connectors: 2, incident_types: 1 }), '2 connectors · 1 type')
  assert.equal(contentsLine({ sigma_rules: 1 }), '1 Sigma rule')
  assert.equal(contentsLine({ sigma_rules: 2700 }), '2700 Sigma rules')
  assert.equal(contentsLine({}), 'Nothing yet')
  assert.deepEqual(contentsOf([{ kind: 'lists' }, { kind: 'lists' }, { kind: 'scripts' }]), { lists: 2, scripts: 1 })
  assert.deepEqual(
    uninstallCounts([{ action: 'remove' }, { action: 'keep' }, { action: 'keep' }, { action: 'gone' }]),
    {
      remove: 1,
      keep: 2,
      gone: 1,
    },
  )
})

const FOUND = {
  packs: [
    {
      id: 'jira-cloud',
      name: 'Jira Cloud',
      vendor: 'Atlassian',
      category: 'Ticketing',
      tags: ['ticketing'],
      connectors: ['Jira Cloud'],
      version: '1.3.0',
      installed: '1.2.0',
      update: true,
    },
    {
      id: 'servicenow',
      name: 'ServiceNow',
      vendor: 'ServiceNow',
      category: 'Ticketing',
      tags: ['ticketing', 'itsm'],
      connectors: ['ServiceNow'],
      description: 'Incidents kept in step both ways.',
      version: '1.0.1',
    },
    {
      id: 'virustotal',
      name: 'VirusTotal',
      vendor: 'Google',
      category: 'Threat intelligence',
      tags: ['threat-intelligence', 'file', 'url'],
      connectors: ['VirusTotal v3'],
      version: '1.0.1',
    },
    {
      id: 'urlhaus',
      name: 'URLhaus',
      vendor: 'abuse.ch',
      tags: ['threat-intelligence', 'url'],
      version: '1.0.1',
      installed: '1.0.1',
    },
    { id: 'tomorrow', name: 'Tomorrow', vendor: 'Acme', tags: ['siem'], version: '2.0.0', needsNik: '9.0' },
  ],
}
const HERE = [
  { id: 'nik', name: 'Nik built-in', version: '6.4.0', builtin: true, items: [] },
  { id: 'jira-cloud', name: 'Jira Cloud', version: '1.2.0', tags: ['ticketing'], items: [] },
  { id: 'urlhaus', name: 'URLhaus', version: '1.0.1', tags: ['threat-intelligence', 'url'], items: [] },
  {
    id: 'ours',
    name: 'Ours',
    version: '0.1.0',
    tags: ['edr'],
    source: 'file',
    items: [{ kind: 'connectors', name: 'our-desk' }],
  },
]

test('a pack is looked for by what is typed, by tags, and without the installed ones', async () => {
  const { filterCards, packCards, searchText, tagCounts, toggled } = await import('./packs.js')
  const cards = packCards(FOUND, HERE)
  const ids = (found) => found.map((card) => card.id).sort()

  // The search looks in the name, the vendor, the category, the tags, the description and the connectors.
  assert.deepEqual(ids(filterCards(cards, 'all', 'google')), ['virustotal'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'TICKETING')), ['jira-cloud', 'servicenow'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'itsm')), ['servicenow'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'in step')), ['servicenow'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'v3')), ['virustotal'])
  // An installed pack that is not in the catalogue is found by the connector it gave.
  assert.deepEqual(ids(filterCards(cards, 'all', 'our-desk')), ['ours'])
  // Every word must be found, wherever it is.
  assert.deepEqual(ids(filterCards(cards, 'all', 'threat  url abuse')), ['urlhaus'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'ticketing google')), [])
  assert.match(searchText(cards[0]), /jira cloud atlassian ticketing ticketing/)

  // A card must have every tag chosen: two tags narrow.
  assert.deepEqual(ids(filterCards(cards, 'all', '', { tags: ['threat-intelligence'] })), ['urlhaus', 'virustotal'])
  assert.deepEqual(ids(filterCards(cards, 'all', '', { tags: ['threat-intelligence', 'file'] })), ['virustotal'])
  assert.deepEqual(ids(filterCards(cards, 'all', 'haus', { tags: ['url'] })), ['urlhaus'])

  // Hiding the installed ones leaves what there is to install; it says nothing of the other two filters.
  assert.deepEqual(ids(filterCards(cards, 'all', '', { hideInstalled: true })), [
    'servicenow',
    'tomorrow',
    'virustotal',
  ])
  assert.deepEqual(ids(filterCards(cards, 'installed', '', { hideInstalled: true })), [
    'jira-cloud',
    'nik',
    'ours',
    'urlhaus',
  ])
  assert.deepEqual(ids(filterCards(cards, 'updates', '', { hideInstalled: true })), ['jira-cloud'])
  assert.deepEqual(ids(filterCards(cards, 'all', '', { hideInstalled: true, tags: ['url'] })), ['virustotal'])

  // The tags there are among the cards shown, each with its count; a chosen one is always listed.
  assert.deepEqual(tagCounts(cards), [
    { tag: 'threat-intelligence', count: 2, chosen: false },
    { tag: 'ticketing', count: 2, chosen: false },
    { tag: 'url', count: 2, chosen: false },
    { tag: 'edr', count: 1, chosen: false },
    { tag: 'file', count: 1, chosen: false },
    { tag: 'itsm', count: 1, chosen: false },
    { tag: 'siem', count: 1, chosen: false },
  ])
  const narrowed = filterCards(cards, 'all', '', { tags: ['file'] })
  assert.deepEqual(
    tagCounts(narrowed, ['file']).map((entry) => `${entry.tag} ${entry.count}${entry.chosen ? ' *' : ''}`),
    ['file 1 *', 'threat-intelligence 1', 'url 1'],
  )
  assert.deepEqual(tagCounts([], ['edr']), [{ tag: 'edr', count: 0, chosen: true }])
  assert.deepEqual(toggled(['a'], 'b'), ['a', 'b'])
  assert.deepEqual(toggled(['a', 'b'], 'a'), ['b'])
})

test('a selection of packs says what can be done with it', async () => {
  const { packCards, selectShown, selectable, selectionActions, filterCards } = await import('./packs.js')
  const cards = packCards(FOUND, HERE)
  const by = Object.fromEntries(cards.map((card) => [card.id, card]))
  // The pack of Nik and one for a later Nik cannot be chosen.
  assert.equal(selectable(by.nik), false)
  assert.equal(selectable(by.tomorrow), false)
  assert.equal(selectable(by.servicenow), true)
  const names = (found) => found.map((card) => card.id).sort()
  const all = selectShown([], cards)
  assert.deepEqual([...all].sort(), ['jira-cloud', 'ours', 'servicenow', 'urlhaus', 'virustotal'])
  const actions = selectionActions(cards, all)
  assert.deepEqual(names(actions.install), ['servicenow', 'virustotal'])
  assert.deepEqual(names(actions.update), ['jira-cloud'])
  // One with an update is installed too: it can be uninstalled.
  assert.deepEqual(names(actions.uninstall), ['jira-cloud', 'ours', 'urlhaus'])
  assert.equal(actions.chosen.length, 5)
  // "Select all shown" adds what is shown to what was chosen, once.
  const shown = filterCards(cards, 'all', '', { tags: ['ticketing'] })
  assert.deepEqual(selectShown(['urlhaus', 'servicenow'], shown).sort(), ['jira-cloud', 'servicenow', 'urlhaus'])
  // A pack that is not listed any more counts for nothing.
  assert.equal(selectionActions(cards, ['gone', 'nik']).chosen.length, 0)
})

test('several packs at once: what is asked of the server and what it answers', async () => {
  const { bulkApplyBody, bulkCounts, bulkPlanBody, bulkPlanLine, bulkResultLine, bulkTitle, mirroringKept } =
    await import('./packs.js')
  assert.deepEqual(bulkPlanBody('install', [{ id: 'b' }, { id: 'a' }]), {
    action: 'install',
    packs: [{ id: 'b' }, { id: 'a' }],
  })
  assert.equal(bulkTitle('install', 3), 'Install 3 packs')
  assert.equal(bulkTitle('uninstall', 1), 'Uninstall 1 pack')
  // The order is the one the server gave (a pack after the ones it requires): it is kept, and what the
  // plan left out is not sent.
  const plan = {
    action: 'install',
    packs: [
      { id: 'base', name: 'Base', ok: true, token: 't-base', counts: { add: 3, update: 1, same: 0, conflict: 0 } },
      { id: 'clash', name: 'Clash', ok: false, why: '1 of its items is in conflict', token: 't-clash' },
      {
        id: 'extras',
        name: 'Extras',
        ok: true,
        token: 't-extras',
        counts: { add: 0, update: 0, same: 2, conflict: 0 },
      },
    ],
  }
  assert.deepEqual(bulkApplyBody(plan), {
    action: 'install',
    packs: [
      { id: 'base', token: 't-base' },
      { id: 'extras', token: 't-extras' },
    ],
  })
  assert.deepEqual(
    bulkApplyBody({
      action: 'uninstall',
      packs: [
        { id: 'extras', ok: true },
        { id: 'base', ok: false },
      ],
    }),
    {
      action: 'uninstall',
      packs: [{ id: 'extras' }],
    },
  )
  assert.deepEqual(bulkCounts(plan.packs), { ok: 2, left: 1 })
  assert.deepEqual(bulkCounts(undefined), { ok: 0, left: 0 })
  assert.equal(bulkPlanLine('install', plan.packs[0]), '3 to add, 1 to update')
  assert.equal(bulkPlanLine('install', plan.packs[1]), '')
  assert.equal(bulkPlanLine('uninstall', { counts: { remove: 4, keep: 1, gone: 0 } }), '4 to remove, 1 to keep')
  assert.equal(bulkPlanLine('uninstall', { counts: { remove: 2, keep: 0, gone: 1 } }), '2 to remove, 1 no longer here')
  assert.equal(bulkResultLine('install', { ok: true, added: 3, updated: 0, same: 1 }), 'installed: 3 added, 1 the same')
  assert.equal(bulkResultLine('update', { ok: true, added: 0, updated: 2, same: 0 }), 'updated: 2 updated')
  assert.equal(bulkResultLine('uninstall', { ok: true, removed: 4, kept: 1 }), 'uninstalled: 4 removed, 1 kept')
  // An update whose mapper stops naming the direction of mirroring says which instances were told it.
  const kept = [{ connector: 'jira-cloud', direction: 'in', instances: ['Jira prod', 'Jira test'] }]
  assert.equal(
    mirroringKept(kept),
    'Mirroring was set to In in Jira prod, Jira test: the mapper said so until now, and the instance says it from now on.',
  )
  assert.equal(mirroringKept([]), '')
  assert.equal(mirroringKept(undefined), '')
  assert.equal(
    bulkResultLine('update', { ok: true, added: 0, updated: 2, same: 1, mirroring: kept }),
    `updated: 2 updated, 1 the same. ${mirroringKept(kept)}`,
  )
  assert.equal(bulkResultLine('uninstall', { ok: false, why: 'It is in use' }), 'not uninstalled: it is in use')
  assert.equal(
    bulkResultLine('install', { ok: false, why: 'It requires the pack "base", which is not installed' }),
    'not installed: it requires the pack "base", which is not installed',
  )
})
