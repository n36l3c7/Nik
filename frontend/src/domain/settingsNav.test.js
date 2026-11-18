import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  SETTINGS_GROUPS,
  filterSettings,
  isSettingsPath,
  resolveSection,
  settingsFromPath,
  settingsPath,
  visibleSettings,
} from './settingsNav.js'

const ids = (groups) => groups.flatMap((group) => group.sections.map((section) => section.id))
const canOf =
  (...granted) =>
  (permission) =>
    granted.includes(permission)

test('every section has an address of its own, and the address leads back to it', () => {
  const seen = new Set()
  for (const id of ids(SETTINGS_GROUPS)) {
    const path = settingsPath(id)
    assert.match(path, /^\/settings\/[a-z]+\/[a-z-]+$/)
    assert.equal(seen.has(path), false, path)
    seen.add(path)
    assert.deepEqual(settingsFromPath(path), { id })
  }
  assert.equal(settingsPath('accounts'), '/settings/access/accounts')
  assert.equal(settingsPath('audit'), '/settings/system/audit-log')
  assert.equal(settingsPath('nope'), '/settings')
})

test('an address that is not a section still opens the page', () => {
  assert.equal(settingsFromPath('/incident/abc'), null)
  assert.equal(settingsFromPath('/settingsx'), null)
  assert.deepEqual(settingsFromPath('/settings'), { id: null })
  assert.deepEqual(settingsFromPath('/settings/'), { id: null })
  assert.deepEqual(settingsFromPath('/settings/access'), { id: 'account' }) // a group: its first section
  assert.deepEqual(settingsFromPath('/settings/audit'), { id: 'audit' }) // the id an older link used
  assert.deepEqual(settingsFromPath('/settings/access/nope'), { id: 'account' })
  assert.deepEqual(settingsFromPath('/settings/nope/nope'), { id: null })
  assert.deepEqual(settingsFromPath('/settings/system/audit-log/'), { id: 'audit' })
  assert.equal(isSettingsPath('/settings/system/backup'), true)
  assert.equal(isSettingsPath('/'), false)
})

test('an account sees the sections its permissions open, and a group with none is not shown', () => {
  assert.deepEqual(ids(visibleSettings(() => true)), ids(SETTINGS_GROUPS))
  assert.deepEqual(ids(visibleSettings(canOf('read'))), ['detection', 'hours', 'allowlist', 'account'])
  assert.deepEqual(ids(visibleSettings(canOf('audit.read'))), ['account', 'audit'])
  assert.deepEqual(
    visibleSettings(canOf('audit.read')).map((group) => group.id),
    ['access', 'system'],
  )
  assert.deepEqual(ids(visibleSettings(canOf('rules.manage'))), ['yara', 'capa', 'flirt', 'account'])
  assert.deepEqual(ids(visibleSettings(() => false)), ['account'])
})

test('the section shown is the one asked for, or the first the account can open', () => {
  const auditor = visibleSettings(canOf('audit.read'))
  assert.equal(resolveSection(auditor, 'audit').id, 'audit')
  assert.equal(resolveSection(auditor, 'accounts').id, 'account') // not theirs: their first one
  assert.equal(resolveSection(auditor, null).id, 'account')
  assert.equal(
    resolveSection(
      visibleSettings(() => true),
      null,
    ).id,
    'detection',
  )
  assert.equal(resolveSection([], 'audit'), null)
})

test('the search box narrows the sections by label, group and keywords', () => {
  const all = visibleSettings(() => true)
  assert.deepEqual(ids(filterSettings(all, '')), ids(all))
  assert.deepEqual(ids(filterSettings(all, 'yara')), ['yara'])
  assert.deepEqual(ids(filterSettings(all, 'RULE sets')), ['yara', 'capa', 'flirt']) // the group's name
  assert.deepEqual(ids(filterSettings(all, 'password')), ['account'])
  assert.deepEqual(ids(filterSettings(all, 'api keys')), ['intel', 'apikeys'])
  assert.deepEqual(ids(filterSettings(all, 'restore')), ['backup'])
  assert.deepEqual(ids(filterSettings(all, 'smtp')), ['automationNetwork'])
  assert.deepEqual(ids(filterSettings(all, 'automation')), [
    'connectors',
    'connections',
    'mappers',
    'fetchStatus',
    'automationNetwork',
    'automationSwitch',
  ])
  assert.deepEqual(ids(filterSettings(all, 'credentials')), ['connections'])
  assert.deepEqual(filterSettings(all, 'zzz'), [])
})
