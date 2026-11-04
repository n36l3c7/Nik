import assert from 'node:assert/strict'
import { test } from 'node:test'
import { getBrowserById } from '../config/browsers.js'
import {
  activeProfileOf,
  browserRowCount,
  flagProfile,
  normalizeBrowserSlot,
  profileLabel,
  profileNameError,
  sortedProfiles,
} from './browserProfiles.js'

const chrome = getBrowserById('chrome')

test('moves a legacy (pre-2.0.0) browser slot into a "Default" profile', () => {
  const legacy = { history: [{ id: 'h1' }], bookmarks: 'bad', meta: { history: { fileName: 'History' } } }
  const slot = normalizeBrowserSlot(legacy, chrome)
  assert.equal(slot.activeProfile, 'default')
  const profile = slot.profiles.default
  assert.equal(profile.name, 'Default')
  assert.deepEqual(profile.history, [{ id: 'h1' }])
  assert.deepEqual(profile.bookmarks, [])
  assert.deepEqual(profile.meta, { history: { fileName: 'History' }, bookmarks: null, shortcuts: null })
})

test('keeps profiles, fixes an invalid active profile and fills defaults', () => {
  const slot = normalizeBrowserSlot(
    {
      activeProfile: 'gone',
      profiles: {
        w: { name: ' Work ', createdAt: '2026-11-04T10:00:00.000Z', history: [{ id: 'x' }] },
        default: { createdAt: '1970-01-01T00:00:00.000Z' },
        junk: 'not a profile',
      },
    },
    chrome,
  )
  assert.deepEqual(Object.keys(slot.profiles).sort(), ['default', 'w'])
  assert.equal(slot.activeProfile, 'default')
  assert.equal(slot.profiles.w.name, 'Work')
  assert.deepEqual(sortedProfiles(slot).map((p) => p.id), ['default', 'w'])
  assert.equal(browserRowCount(slot), 1)
  assert.equal(activeProfileOf(slot).id, 'default')
})

test('always yields one profile for empty or missing data', () => {
  for (const raw of [undefined, null, { profiles: {} }]) {
    const slot = normalizeBrowserSlot(raw, chrome)
    assert.deepEqual(Object.keys(slot.profiles), ['default'])
  }
})

test('validates profile names case-insensitively per browser', () => {
  const slot = normalizeBrowserSlot({ profiles: { default: {}, w: { name: 'Work' } } }, chrome)
  assert.match(profileNameError(slot, '  '), /Enter a profile name/)
  assert.match(profileNameError(slot, 'work'), /already exists/)
  assert.equal(profileNameError(slot, 'Work', 'w'), null)
  assert.equal(profileNameError(slot, 'Personal'), null)
  assert.match(profileNameError(slot, 'x'.repeat(61)), /at most 60/)
})

test('shows the profile name only when a browser has several profiles', () => {
  const one = normalizeBrowserSlot(undefined, chrome)
  const two = normalizeBrowserSlot({ profiles: { default: {}, w: { name: 'Work' } } }, chrome)
  assert.equal(profileLabel('Chrome', one, one.profiles.default), 'Chrome')
  assert.equal(profileLabel('Chrome', two, two.profiles.w), 'Chrome · Work')
})

test('resolves the profile of a flag, including renamed and deleted ones', () => {
  const browsers = { chrome: normalizeBrowserSlot({ profiles: { w: { name: 'Work (renamed)' } } }, chrome) }
  assert.equal(flagProfile(browsers, { browserId: 'bash' }), null)
  assert.deepEqual(flagProfile(browsers, { browserId: 'chrome', profileId: 'w', profileName: 'Work' }), {
    name: 'Work (renamed)',
    deleted: false,
  })
  assert.deepEqual(flagProfile(browsers, { browserId: 'chrome', profileId: 'x', profileName: 'Old' }), {
    name: 'Old',
    deleted: true,
  })
})
