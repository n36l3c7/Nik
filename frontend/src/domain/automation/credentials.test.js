import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  createBody,
  credentialChoices,
  credentialForm,
  credentialProblem,
  filterCredentials,
  keepable,
  keptKind,
  mentionsCredential,
  nameProblem,
  pairOf,
  parseReference,
  pickedReference,
  pickerOptions,
  referenceText,
  secretMode,
  storedReference,
  suggestedName,
  updateBody,
  usedIn,
  valueForMode,
} from './credentials.js'

const VT = { id: '1', name: 'vt_key', kind: 'secret', username: '', title: 'VirusTotal', usedBy: [] }
const PROXY = { id: '2', name: 'proxy', kind: 'pair', username: 'svc-proxy', title: '', usedBy: [] }
const ALL = [VT, PROXY]

test('a field names a credential with one text, and that text is read back', () => {
  assert.equal(referenceText('vt_key'), '{{ credentials.vt_key }}')
  assert.equal(referenceText('proxy', 'password'), '{{ credentials.proxy.password }}')
  assert.deepEqual(parseReference('{{ credentials.vt_key }}'), { name: 'vt_key', part: '' })
  assert.deepEqual(parseReference('  {{credentials.my-proxy.username}} '), { name: 'my-proxy', part: 'username' })
  // Anything else is something that was typed: a text around it, a filter, a part that does not exist.
  for (const typed of ['', 'k-123', 'Bearer {{ credentials.vt_key }}', '{{ credentials.vt_key | upper }}']) {
    assert.equal(parseReference(typed), null, typed)
  }
  assert.equal(parseReference('{{ credentials.vt_key.token }}'), null)
  assert.equal(parseReference('{{ secret.api_key }}'), null)
  assert.equal(mentionsCredential('Bearer {{ credentials.vt_key }}'), true)
  assert.equal(mentionsCredential('{{credentials'), true)
  assert.equal(mentionsCredential('credentials.vt_key'), false)
})

test('a pair fills the user name and the password together where the connector has both', () => {
  const basic = ['username', 'password']
  assert.deepEqual(pairOf(basic), ['username', 'password'])
  assert.deepEqual(pairOf(['client_id', 'client_secret']), ['client_id', 'client_secret'])
  assert.equal(pairOf(['value']), null)
  assert.deepEqual(credentialChoices(ALL, 'password', basic), [
    {
      value: '{{ credentials.proxy.password }}',
      label: 'proxy (svc-proxy)',
      fills: { username: '{{ credentials.proxy.username }}', password: '{{ credentials.proxy.password }}' },
    },
    // A secret is a password too; it leaves the user name as it is.
    { value: '{{ credentials.vt_key }}', label: 'vt_key', fills: { password: '{{ credentials.vt_key }}' } },
  ])
  // The field of a user name takes pairs only.
  assert.deepEqual(
    credentialChoices(ALL, 'username', basic).map((choice) => choice.value),
    ['{{ credentials.proxy.username }}'],
  )
  // OAuth2 client credentials are a pair: the client id is its user name.
  assert.deepEqual(credentialChoices([PROXY], 'client_secret', ['client_id', 'client_secret'])[0].fills, {
    client_id: '{{ credentials.proxy.username }}',
    client_secret: '{{ credentials.proxy.password }}',
  })
})

test('a field that is one value takes a secret, or the password of a pair', () => {
  assert.deepEqual(credentialChoices(ALL, 'value', ['value']), [
    {
      value: '{{ credentials.proxy.password }}',
      label: 'proxy (its password)',
      fills: { value: '{{ credentials.proxy.password }}' },
    },
    { value: '{{ credentials.vt_key }}', label: 'vt_key', fills: { value: '{{ credentials.vt_key }}' } },
  ])
  // The third secret of a session (its API key) is one value, beside the pair.
  const session = ['username', 'password', 'api_key']
  assert.deepEqual(
    credentialChoices(ALL, 'api_key', session).map((choice) => Object.keys(choice.fills)),
    [['api_key'], ['api_key']],
  )
  assert.deepEqual(credentialChoices(null, 'value', ['value']), [])
})

test('the way a field is given: what was chosen, then what it holds, then what is stored', () => {
  const choices = credentialChoices(ALL, 'value', ['value'])
  assert.equal(secretMode({ chosen: 'typed', reference: '{{ credentials.vt_key }}', choices }), 'typed')
  assert.equal(secretMode({ chosen: 'credential', typed: 'abc' }), 'credential')
  assert.equal(secretMode({ typed: '{{ credentials.vt_key }}' }), 'credential') // written by hand
  assert.equal(secretMode({ typed: 'k-123', reference: '{{ credentials.vt_key }}' }), 'typed')
  assert.equal(secretMode({ stored: true, reference: '{{ credentials.vt_key }}' }), 'credential')
  assert.equal(secretMode({ stored: true, choices }), 'typed') // a typed secret is stored: it stays typed
  // Nothing yet: from a credential when one fits (an instance made again), typed otherwise.
  assert.equal(secretMode({ choices }), 'credential')
  assert.equal(secretMode({ choices: [] }), 'typed')
  assert.equal(secretMode({}), 'typed')
})

test('the picker shows the credential that was chosen, or the one that is stored', () => {
  const held = { value: { name: 'vt_key', part: '', missing: false } }
  assert.equal(storedReference(held, 'value'), '{{ credentials.vt_key }}')
  assert.equal(storedReference(held, 'other'), '')
  assert.equal(storedReference(undefined, 'value'), '')
  assert.equal(pickedReference('', '{{ credentials.vt_key }}'), '{{ credentials.vt_key }}')
  assert.equal(
    pickedReference(' {{ credentials.proxy.password }}', '{{ credentials.vt_key }}'),
    '{{ credentials.proxy.password }}',
  )
  assert.equal(pickedReference('typed', ''), '')
  const choices = credentialChoices(ALL, 'value', ['value'])
  assert.equal(pickerOptions(choices, '{{ credentials.vt_key }}', held.value), choices)
  assert.equal(pickerOptions(choices, '', null), choices)
  // A credential that is stored but cannot be chosen any more is still shown, as what it is.
  const gone = pickerOptions(choices, '{{ credentials.old }}', { name: 'old', part: '', missing: true })
  assert.deepEqual(gone[0], { value: '{{ credentials.old }}', label: 'old (does not exist any more)', fills: {} })
  assert.equal(gone.length, choices.length + 1)
  assert.equal(pickerOptions([], '{{ credentials.proxy.username }}', { missing: false })[0].label, 'proxy')
})

test('changing the way of a field drops what belongs to the other way', () => {
  assert.equal(valueForMode('{{ credentials.vt_key }}', 'typed'), '')
  assert.equal(valueForMode('k-123', 'typed'), 'k-123')
  assert.equal(valueForMode('k-123', 'credential'), '')
  assert.equal(valueForMode('{{ credentials.vt_key }}', 'credential'), '{{ credentials.vt_key }}')
  assert.equal(valueForMode(undefined, 'typed'), '')
})

test('a typed secret that is stored can be kept as a credential, as a pair when both parts are', () => {
  const basic = ['username', 'password']
  const stored = { username: true, password: true }
  assert.equal(keepable(true, {}, 'password'), true)
  assert.equal(keepable(false, {}, 'password'), false)
  assert.equal(keepable(true, { password: { name: 'proxy', part: 'password' } }, 'password'), false)
  // The user name of a pair is kept with its password, from the password: not by itself.
  assert.equal(keepable(true, {}, 'username', basic), false)
  assert.equal(keepable(true, {}, 'password', basic), true)
  assert.equal(keepable(true, {}, 'client_id', ['client_id', 'client_secret']), false)
  assert.equal(keepable(true, {}, 'value', ['value']), true)
  assert.equal(keptKind('password', basic, stored, {}), 'pair')
  assert.equal(keptKind('username', basic, stored, {}), 'pair')
  // One part is a credential already, or is not stored: the other is kept alone.
  assert.equal(keptKind('password', basic, stored, { username: { name: 'proxy', part: 'username' } }), 'secret')
  assert.equal(keptKind('password', basic, { password: true }, {}), 'secret')
  assert.equal(keptKind('value', ['value'], { value: true }, {}), 'secret')
  assert.equal(keptKind('api_key', ['username', 'password', 'api_key'], { ...stored, api_key: true }, {}), 'secret')
})

test('a name is suggested from the instance, and checked as the server checks it', () => {
  assert.equal(suggestedName('Shodan production'), 'shodan_production')
  assert.equal(suggestedName('  9 Lives — Proxy (EU) '), 'lives_proxy_eu')
  assert.equal(suggestedName('x'.repeat(60)).length, 40)
  assert.equal(suggestedName('***'), '')
  assert.equal(nameProblem(''), 'A name is needed')
  assert.match(nameProblem('Vt Key'), /lower-case letter/)
  assert.match(nameProblem('1key'), /lower-case letter/)
  assert.match(nameProblem('a'.repeat(41)), /lower-case letter/)
  assert.equal(nameProblem('vt_key', ['vt_key']), 'A credential called "vt_key" exists already')
  assert.equal(nameProblem('vt-key_2', ['vt_key']), null)
})

test('the form of a credential: what is needed, what is sent, and a value that stays when left empty', () => {
  const empty = credentialForm()
  assert.deepEqual(empty, { name: '', title: '', kind: 'secret', username: '', value: '' })
  assert.equal(credentialProblem(empty), 'A name is needed')
  assert.equal(credentialProblem({ ...empty, name: 'vt_key' }), 'The value is needed')
  assert.equal(credentialProblem({ ...empty, name: 'vt_key', value: 'k' }), null)
  assert.equal(
    credentialProblem({ ...empty, name: 'vt_key', value: 'k' }, { taken: ['vt_key'] }).includes('exists'),
    true,
  )
  const pair = { ...empty, name: 'proxy', kind: 'pair' }
  assert.equal(credentialProblem(pair), 'The user name is needed')
  assert.equal(credentialProblem({ ...pair, username: 'svc' }), 'The password is needed')
  assert.match(
    credentialProblem({ ...pair, username: 'svc', value: '{{ credentials.vt_key }}' }),
    /not the name of another/,
  )
  assert.deepEqual(createBody({ ...pair, username: ' svc ', value: 'p w ', title: ' Proxy ' }), {
    name: 'proxy',
    title: 'Proxy',
    kind: 'pair',
    username: 'svc',
    value: 'p w ', // a value is sent as it was typed
  })
  assert.deepEqual(createBody({ ...empty, name: 'vt_key', value: 'k', username: 'ignored' }), {
    name: 'vt_key',
    title: '',
    kind: 'secret',
    value: 'k',
  })
  // Editing: the value is never shown, and left empty it stays; only what changed is sent.
  const form = credentialForm(PROXY)
  assert.deepEqual(form, { name: 'proxy', title: '', kind: 'pair', username: 'svc-proxy', value: '' })
  assert.equal(credentialProblem(form, { existing: PROXY }), null)
  assert.deepEqual(updateBody(form, PROXY), {})
  assert.deepEqual(updateBody({ ...form, title: 'The proxy', value: 'new' }, PROXY), {
    title: 'The proxy',
    value: 'new',
  })
  assert.deepEqual(updateBody({ ...form, name: 'proxy2', username: 'other' }, PROXY), {
    name: 'proxy2',
    username: 'other',
  })
  assert.deepEqual(updateBody({ ...credentialForm(VT), username: 'x' }, VT), {})
})

test('where a credential is used: one line an instance, on the tab that holds the key', () => {
  const usedBy = [
    { instance: 'i1', name: 'Shodan production', connectorName: 'Shodan', key: 'main', keyName: 'Key 1' },
    { instance: 'i1', name: 'Shodan production', connectorName: 'Shodan', key: 'k2', keyName: 'spare' },
    { instance: 'i2', name: 'Shodan lab', connectorName: 'Shodan', key: 'k9', keyName: 'lab' },
  ]
  assert.deepEqual(usedIn(usedBy), [
    { instance: 'i1', name: 'Shodan production', connectorName: 'Shodan', tab: 'connection', keys: ['spare'] },
    { instance: 'i2', name: 'Shodan lab', connectorName: 'Shodan', tab: 'keys', keys: ['lab'] },
  ])
  assert.deepEqual(usedIn(undefined), [])
})

test('the list is narrowed by a name, a description, a user name or an instance', () => {
  const used = { ...VT, usedBy: [{ instance: 'i1', name: 'Shodan production', key: 'main' }] }
  const all = [used, PROXY]
  assert.deepEqual(filterCredentials(all, ''), all)
  assert.deepEqual(filterCredentials(all, 'virus'), [used])
  assert.deepEqual(filterCredentials(all, 'SVC'), [PROXY])
  assert.deepEqual(filterCredentials(all, 'shodan prod'), [used])
  assert.deepEqual(filterCredentials(all, 'nothing'), [])
  assert.deepEqual(filterCredentials(null, 'x'), [])
})
