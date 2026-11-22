import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  INSTANCE_TABS,
  SETTINGS_GROUPS,
  credentialFromPath,
  credentialPath,
  filterSettings,
  instanceFromPath,
  instancePath,
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
  assert.deepEqual(ids(visibleSettings(canOf('read'))), ['detection', 'hours', 'allowlist', 'account', 'bulk'])
  assert.deepEqual(ids(visibleSettings(canOf('audit.read'))), ['account', 'audit'])
  assert.deepEqual(
    visibleSettings(canOf('audit.read')).map((group) => group.id),
    ['access', 'system'],
  )
  assert.deepEqual(ids(visibleSettings(canOf('rules.manage'))), [
    'yara',
    'capa',
    'flirt',
    'scriptSignatures',
    'account',
  ])
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
  assert.deepEqual(ids(filterSettings(all, 'RULE sets')), ['yara', 'capa', 'flirt', 'scriptSignatures']) // the group's name
  assert.deepEqual(ids(filterSettings(all, 'password')), ['account'])
  assert.deepEqual(ids(filterSettings(all, 'api keys')), ['intel', 'apikeys'])
  assert.deepEqual(ids(filterSettings(all, 'restore')), ['backup'])
  assert.deepEqual(ids(filterSettings(all, 'smtp')), ['automationNetwork'])
  assert.deepEqual(ids(filterSettings(all, 'automation')), [
    'contentPacks',
    'connectors',
    'credentials',
    'automationNetwork',
    'automationSwitch',
  ])
  // The credentials of an instance are typed in Connectors, or kept once in Credentials.
  assert.deepEqual(ids(filterSettings(all, 'credentials')), ['connectors', 'credentials'])
  assert.deepEqual(ids(filterSettings(all, 'stored secrets')), ['credentials'])
  // An address of 4.x that named the connections opens the connectors, where their instances are.
  assert.deepEqual(settingsFromPath('/settings/automation/connections'), { id: 'connectors' })
  // The group alone opens its first section: the packs, which bring the rest.
  assert.deepEqual(settingsFromPath('/settings/automation'), { id: 'contentPacks' })
  assert.deepEqual(filterSettings(all, 'zzz'), [])
})

test('fetching, the classifier and the mappers are set in the instance: their pages are gone and their addresses open Connectors', () => {
  const all = ids(SETTINGS_GROUPS)
  assert.equal(all.includes('mappers'), false)
  assert.equal(all.includes('fetchStatus'), false)
  // The addresses those pages had, in a bookmark or a notification of an older release.
  assert.deepEqual(settingsFromPath('/settings/automation/fetch-status'), { id: 'connectors' })
  assert.deepEqual(settingsFromPath('/settings/automation/classifiers-and-mappers'), { id: 'connectors' })
  assert.equal(instanceFromPath('/settings/automation/fetch-status'), null)
  // What used to find them in the search box finds Connectors.
  const shown = visibleSettings(() => true)
  for (const typed of ['fetch status', 'classifier', 'mappers', 'look-back', 'reset last run', 'paused']) {
    assert.deepEqual(ids(filterSettings(shown, typed)).includes('connectors'), true, typed)
  }
  assert.deepEqual(ids(filterSettings(shown, 'mappers')), ['connectors'])
})

test('an address names an instance and the part of its form', () => {
  assert.equal(instancePath('abc123'), '/settings/automation/connectors/abc123')
  assert.equal(instancePath('abc123', 'connection'), '/settings/automation/connectors/abc123')
  assert.equal(instancePath('abc123', 'fetch'), '/settings/automation/connectors/abc123/fetch')
  assert.equal(instancePath('abc123', 'nope'), '/settings/automation/connectors/abc123')
  assert.equal(instancePath('a b'), '/settings/automation/connectors/a%20b')
  for (const tab of INSTANCE_TABS) {
    assert.deepEqual(instanceFromPath(instancePath('abc123', tab)), { instanceId: 'abc123', tab })
  }
  assert.deepEqual(instanceFromPath('/settings/automation/connectors/a%20b/mappers/'), {
    instanceId: 'a b',
    tab: 'mappers',
  })
  assert.deepEqual(instanceFromPath('/settings/automation/connectors/abc123/nope'), {
    instanceId: 'abc123',
    tab: 'connection',
  })
  // The page alone, another section, another page: no instance.
  assert.equal(instanceFromPath('/settings/automation/connectors'), null)
  assert.equal(instanceFromPath('/settings/automation/connectors/'), null)
  assert.equal(instanceFromPath('/settings/automation/content-packs/abc123'), null)
  assert.equal(instanceFromPath('/incident/abc123'), null)
  // The address of an instance is still the Connectors section.
  assert.deepEqual(settingsFromPath('/settings/automation/connectors/abc123/fetch'), { id: 'connectors' })
})

test('an address of Credentials points at one credential, by its name', () => {
  assert.equal(settingsPath('credentials'), '/settings/automation/credentials')
  assert.equal(credentialPath('vt_key'), '/settings/automation/credentials/vt_key')
  assert.equal(credentialFromPath(credentialPath('vt-key_2')), 'vt-key_2')
  assert.equal(credentialFromPath('/settings/automation/credentials/vt_key/'), 'vt_key')
  assert.equal(credentialFromPath('/settings/automation/credentials'), '')
  assert.equal(credentialFromPath('/settings/automation/connectors/vt_key'), '')
  assert.equal(credentialFromPath('/incident/vt_key'), '')
  // It is still the Credentials section, for who manages the connectors and nobody else.
  assert.deepEqual(settingsFromPath(credentialPath('vt_key')), { id: 'credentials' })
  const sections = (can) => visibleSettings(can).flatMap((group) => group.sections.map((section) => section.id))
  assert.equal(sections(canOf('connectors.manage')).includes('credentials'), true)
  assert.equal(sections(canOf('automation.edit', 'automation.run', 'read', 'write')).includes('credentials'), false)
})
