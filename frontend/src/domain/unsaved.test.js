import assert from 'node:assert/strict'
import { test } from 'node:test'
import { canSaveAll, lostBy, saveAll, sentenceOf, sentenceText, staysAt, withEntry, withoutEntry } from './unsaved.js'

const editor = { id: 'a', what: 'The playbook', name: 'Phishing triage', path: '/automation/playbooks/p1/settings' }
const dialog = { id: 'b', what: 'The new task', path: '/incident/i1' }

test('a surface enters the list once and leaves it by its id', () => {
  let entries = withEntry([], editor)
  entries = withEntry(entries, dialog)
  entries = withEntry(entries, { ...editor, name: 'Renamed' })
  assert.deepEqual(
    entries.map((entry) => entry.id),
    ['b', 'a'],
  )
  assert.equal(entries[1].name, 'Renamed')
  assert.deepEqual(withoutEntry(entries, 'a'), [dialog])
  assert.deepEqual(withoutEntry(entries, 'nothing'), entries)
})

test('a surface stays at the address it was changed at, and under an indicator drawn over it', () => {
  assert.equal(staysAt(editor, '/automation/playbooks/p1/settings'), true)
  assert.equal(staysAt(editor, '/automation/playbooks/p1/settings?x=1'), true)
  assert.equal(staysAt(editor, '/automation/playbooks/p1'), false)
  assert.equal(staysAt(editor, '/ioc/domain/example.org'), true)
  assert.equal(staysAt(editor, '/iocs'), false)
})

test('what is written on an incident stays under the pages drawn over it', () => {
  assert.equal(staysAt(dialog, '/settings/platform/sla'), true)
  assert.equal(staysAt(dialog, '/tasks'), true)
  assert.equal(staysAt(dialog, '/automation/playbooks'), true)
  // The dashboards, the playground and the list of incidents take its place.
  assert.equal(staysAt(dialog, '/dashboards'), false)
  assert.equal(staysAt(dialog, '/incidents'), false)
  assert.equal(staysAt(dialog, '/incident/i2'), false)
  // A page drawn over the incident is not kept by another one.
  assert.equal(staysAt(editor, '/settings/platform/sla'), false)
})

test('a form with an address per tab says where it stays', () => {
  const form = { id: 'c', what: 'The instance', path: '/settings/x/instances/7', stays: (path) => path.includes('/7') }
  assert.equal(staysAt(form, '/settings/x/instances/7/keys'), true)
  assert.equal(staysAt(form, '/settings/x/instances/8'), false)
})

test('what a move would lose', () => {
  const entries = [editor, dialog]
  // Anywhere: everything.
  assert.deepEqual(lostBy(entries), entries)
  // A change of address: what does not stay there.
  assert.deepEqual(lostBy(entries, { path: '/incident/i1' }), [editor])
  assert.deepEqual(lostBy(entries, { path: '/dashboards' }), entries)
  // Closing one dialog: that dialog.
  assert.deepEqual(lostBy(entries, { only: 'b' }), [dialog])
  assert.deepEqual(lostBy(entries, { only: 'gone' }), [])
  assert.deepEqual(lostBy([], { path: '/tasks' }), [])
  // What is sent on the way out is never lost by a move inside the application.
  const canvas = { id: 'c', what: 'The playbook', path: '/automation/playbooks/p1', sent: true }
  assert.deepEqual(lostBy([canvas, dialog]), [dialog])
  assert.deepEqual(lostBy([canvas], { path: '/dashboards' }), [])
  // Another item of a list on one screen: what is edited on that screen, not what waits under it.
  assert.deepEqual(lostBy(entries, { here: '/automation/playbooks/p1/settings' }), [editor])
  assert.deepEqual(lostBy(entries, { here: '/settings/platform/lists' }), [])
  // The form that is being saved moves on: the others are what it would lose.
  assert.deepEqual(lostBy(entries, { except: 'b' }), [editor])
  assert.deepEqual(lostBy(entries, { except: 'a', path: '/incident/i1' }), [])
})

test('the question names what is unsaved', () => {
  assert.deepEqual(sentenceOf(editor), {
    before: 'The playbook ',
    name: 'Phishing triage',
    after: ' has changes that are not saved.',
  })
  assert.equal(sentenceText(editor), 'The playbook Phishing triage has changes that are not saved.')
  assert.equal(sentenceText(dialog), 'The new task has changes that are not saved.')
  assert.equal(sentenceText({ id: 'x' }), 'This form has changes that are not saved.')
  // What is not a change that was typed says its own sentence.
  assert.equal(
    sentenceText({ id: 'y', what: 'Codes', sentence: 'The codes are shown only now. ' }),
    'The codes are shown only now.',
  )
})

test('"Save and leave" needs every surface to know how to save', async () => {
  const saved = []
  const first = { ...editor, save: async () => saved.push('a') }
  const second = { ...dialog, save: async () => saved.push('b') }
  assert.equal(canSaveAll([first, dialog]), false)
  assert.equal(canSaveAll([]), false)
  assert.equal(canSaveAll([first, second]), true)
  assert.equal(await saveAll([first, second]), null)
  assert.deepEqual(saved, ['a', 'b'])
})

test('a save that fails stops the others and says why', async () => {
  const saved = []
  const refused = { ...editor, save: async () => false }
  const broken = {
    ...editor,
    save: async () => {
      throw new Error('the name is taken')
    },
  }
  const after = { ...dialog, save: async () => saved.push('b') }
  assert.equal(await saveAll([refused, after]), 'The playbook Phishing triage was not saved.')
  assert.equal(await saveAll([broken, after]), 'It was not saved: the name is taken')
  assert.deepEqual(saved, [])
})
