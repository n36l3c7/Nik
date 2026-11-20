import assert from 'node:assert/strict'
import { test } from 'node:test'
import { authOf, fieldsOf, formProblem, instanceTabs, payloadOf, problemLines, startingValues } from './instances.js'

const CONNECTOR = {
  id: 'acme',
  name: 'Acme Desk',
  configuration: [
    { name: 'url', label: 'Instance address', type: 'url', required: true },
    { name: 'region', type: 'choice', choices: ['eu', 'us'], default: 'eu' },
    { name: 'page_size', type: 'number' },
    { name: 'verify', type: 'bool' },
    { name: 'signing_key', type: 'secret', help: 'From the admin console' },
    { name: 'credentials', type: 'basic' },
  ],
  secrets: ['signing_key', 'username', 'password'],
}

test('the form of a connection: plain values, then the parts of its credentials', () => {
  const fields = fieldsOf(CONNECTOR)
  assert.deepEqual(
    fields.map((field) => [field.name, field.label, field.kind, field.masked]),
    [
      ['url', 'Instance address', 'config', false],
      ['region', 'Region', 'config', false],
      ['page_size', 'Page size', 'config', false],
      ['verify', 'Verify', 'config', false],
      ['signing_key', 'Signing key', 'secret', true],
      ['username', 'User name', 'secret', false],
      ['password', 'Password', 'secret', true],
    ],
  )
  assert.equal(fields[1].placeholder, 'eu')
  assert.equal(fields[4].help, 'From the admin console')
  assert.equal(authOf(CONNECTOR), 'a user name and a password')
  assert.equal(authOf({ configuration: [{ name: 'url', type: 'url' }] }), '')
  // A key that goes in the address is credentials too: a secret of the instance, not a field of the form.
  const keyed = { configuration: [{ name: 'credentials', type: 'query', param: 'key' }], secrets: ['value'] }
  assert.equal(authOf(keyed), 'a key sent in the address')
  assert.deepEqual(
    fieldsOf(keyed).map((field) => [field.name, field.kind]),
    [['value', 'secret']],
  )
  assert.deepEqual(fieldsOf(null), [])
  // Credentials of one value are one field: it is called, and explained, as the connector says.
  const said = {
    configuration: [
      { name: 'api_key', label: 'API key', type: 'header', help: 'Optional: left empty, less is answered' },
    ],
    secrets: ['value'],
  }
  assert.deepEqual(
    fieldsOf(said).map((field) => [field.name, field.label, field.help, field.masked]),
    [['value', 'API key', 'Optional: left empty, less is answered', true]],
  )
  // One the connector did not name (the server then gives the name of the entry as its label) is a key.
  const unnamed = { configuration: [{ name: 'credentials', label: 'Credentials', type: 'bearer' }], secrets: ['token'] }
  assert.deepEqual(
    fieldsOf(unnamed).map((field) => [field.label, field.help]),
    [['Token', '']],
  )
  assert.equal(fieldsOf(keyed)[0].label, 'Key')
  // The parts of other credentials keep their own names, whatever the entry is called.
  const basic = {
    configuration: [{ name: 'credentials', label: 'Service account', type: 'basic' }],
    secrets: ['username', 'password'],
  }
  assert.deepEqual(
    fieldsOf(basic).map((field) => field.label),
    ['User name', 'Password'],
  )
})

test('a form starts from the plain values, and never from a secret', () => {
  const connection = { config: { url: 'https://desk.example.com', verify: true }, secrets: { password: true } }
  assert.deepEqual(startingValues(CONNECTOR, connection), {
    url: 'https://desk.example.com',
    region: '',
    page_size: '',
    verify: true,
    signing_key: '',
    username: '',
    password: '',
  })
  assert.equal(startingValues(CONNECTOR).verify, false)
})

test('what is sent: values by their type, a secret only when typed or removed', () => {
  const values = {
    url: ' https://desk.example.com/api ',
    region: '',
    page_size: '50',
    verify: true,
    signing_key: '',
    username: 'svc',
    password: '',
  }
  assert.deepEqual(payloadOf(CONNECTOR, values), {
    config: { url: 'https://desk.example.com/api', page_size: 50, verify: true },
    secrets: { username: 'svc' },
  })
  assert.deepEqual(payloadOf(CONNECTOR, values, ['password', 'username']).secrets, { username: '', password: '' })
})

test('what keeps a form from being sent', () => {
  const good = { url: 'https://desk.example.com', page_size: '' }
  assert.equal(formProblem(CONNECTOR, 'Acme production', good), null)
  assert.equal(formProblem(CONNECTOR, '  ', good), 'A name is needed')
  assert.equal(formProblem(CONNECTOR, 'x', { url: '' }), 'Instance address is needed')
  assert.equal(formProblem(CONNECTOR, 'x', { url: 'desk.example.com' }), 'Instance address is an https:// address')
  assert.equal(formProblem(CONNECTOR, 'x', { ...good, page_size: 'many' }), 'Page size is a number')
})

test('the problems of a file, line by line', () => {
  assert.deepEqual(
    problemLines([
      { line: 12, message: '"methd" is not a key that is known here', where: 'commands[0].request.methd' },
      { line: 0, message: 'The file is larger than 256 kB' },
    ]),
    [
      {
        key: '12:"methd" is not a key that is known here',
        line: 12,
        text: '"methd" is not a key that is known here',
        where: 'commands[0].request.methd',
      },
      { key: '0:The file is larger than 256 kB', line: null, text: 'The file is larger than 256 kB', where: '' },
    ],
  )
  assert.deepEqual(problemLines(null), [])
})

test('connectors are listed with their instances, and narrowed by words and by a filter', async () => {
  const { capabilities, connectorRows, instancesText } = await import('./instances.js')
  const connectors = [
    { id: 'snow', name: 'ServiceNow', description: 'The service desk', commands: [1, 2, 3], fetch: {}, mirror: {} },
    { id: 'jira', name: 'Jira Cloud', description: 'Issues', commands: [1] },
    { id: 's1', name: 'SentinelOne', description: 'Endpoints', commands: [] },
  ]
  const instances = [
    { id: 'b', connector: 'snow', name: 'test desk', host: 'acmetest.example', enabled: false },
    { id: 'a', connector: 'snow', name: 'Production desk', host: 'acme.example', enabled: true },
    { id: 'c', connector: 'jira', name: 'Board', host: 'acme.atlassian.example', enabled: false },
  ]
  assert.equal(capabilities(connectors[0]), '3 commands · fetch · mirror')
  assert.equal(capabilities(connectors[1]), '1 command')
  assert.equal(capabilities({ name: 'unreadable' }), '')

  const { rows, counts } = connectorRows(connectors, instances)
  assert.deepEqual(counts, { all: 3, enabled: 1, unused: 1 })
  assert.deepEqual(
    rows.map((row) => [row.id, row.enabled, row.instances.map((instance) => instance.name)]),
    [
      ['snow', true, ['Production desk', 'test desk']],
      ['jira', false, ['Board']],
      ['s1', false, []],
    ],
  )
  assert.deepEqual(
    rows.map((row) => instancesText(row.instances)),
    ['2 instances · 1 on', '1 instance · off', 'not configured'],
  )
  assert.equal(instancesText([{ enabled: true }]), '1 instance · on')

  const ids = (options) => connectorRows(connectors, instances, options).rows.map((row) => row.id)
  assert.deepEqual(ids({ filter: 'enabled' }), ['snow'])
  assert.deepEqual(ids({ filter: 'unused' }), ['s1'])
  assert.deepEqual(ids({ query: 'desk' }), ['snow'])
  assert.deepEqual(ids({ query: 'ATLASSIAN' }), ['jira']) // the host of an instance
  assert.deepEqual(ids({ query: 'acme example' }), ['snow', 'jira'])
  assert.deepEqual(ids({ query: 'desk', filter: 'unused' }), [])
  // The counts of the filters do not follow what is typed.
  assert.deepEqual(connectorRows(connectors, instances, { query: 'zzz' }).counts, { all: 3, enabled: 1, unused: 1 })
  assert.deepEqual(connectorRows(null, null).rows, [])
})

test('the keys of an instance: what is sent, what stops the form', async () => {
  const { KEY_MODES, editableKeys, keyFields, keyShare, keyUse, keysPayload, keysProblem, newKey, takesKeys } =
    await import('./instances.js')
  const connector = {
    name: 'Radar',
    secrets: ['api_key'],
    configuration: [
      { name: 'url', type: 'url' },
      { name: 'api_key', type: 'secret', label: 'API key' },
    ],
  }
  assert.deepEqual(
    keyFields(connector).map((field) => field.name),
    ['api_key'],
  )
  assert.equal(takesKeys(connector), true)
  assert.equal(takesKeys({ ...connector, native: 'mail' }), false)
  assert.equal(takesKeys({ configuration: [{ name: 'url', type: 'url' }], secrets: [] }), false)
  assert.deepEqual(
    KEY_MODES.map((mode) => mode.id),
    ['each', 'until_exhausted', 'least_used', 'reserve'],
  )

  const instance = {
    keys: [
      { id: 'main', name: 'personal', usedToday: 500, state: 'used up' },
      { id: 'ab12', name: 'lab', usedToday: 190, state: 'in use' },
    ],
    keyPolicy: { mode: 'until_exhausted', perMinute: 4, perDay: 500, whenExhausted: 'wait', cacheHours: 24 },
  }
  const keys = editableKeys(instance)
  const added = { ...newKey(connector, keys.length), name: 'spare' }
  assert.equal(added.isNew, true)
  assert.deepEqual(added.values, { api_key: '' })
  assert.equal(keysProblem(connector, [...keys, added], instance.keyPolicy), '"spare" has no credential yet')
  added.values.api_key = 'k-3'
  assert.equal(keysProblem(connector, [...keys, added], instance.keyPolicy), null)
  assert.equal(
    keysProblem(connector, [...keys, { ...added, name: 'LAB' }], instance.keyPolicy),
    'Two keys are called "LAB"',
  )
  assert.equal(keysProblem(connector, [{ ...keys[0], name: ' ' }], instance.keyPolicy), 'A key needs a name')
  assert.equal(
    keysProblem(connector, keys, { ...instance.keyPolicy, perMinute: -1 }),
    'Requests a minute is a whole number, 0 for none',
  )
  // The first key is named, the others are sent in their order; a secret only when it was typed.
  assert.deepEqual(keysPayload([keys[0], added, keys[1]], { ...instance.keyPolicy, perDay: '500' }), {
    mainName: 'personal',
    keys: [
      { name: 'spare', secrets: { api_key: 'k-3' } },
      { id: 'ab12', name: 'lab' },
    ],
    keyPolicy: { mode: 'until_exhausted', perMinute: 4, perDay: 500, whenExhausted: 'wait', cacheHours: 24 },
  })
  assert.equal(keyUse(keys[1], instance.keyPolicy), '190 / 500')
  assert.equal(keyUse(keys[1], { perDay: 0 }), '190')
  assert.equal(keyShare(keys[0], instance.keyPolicy), 1)
  assert.equal(keyShare(keys[1], { perDay: 0 }), 0)
})

test('the form of an instance has the parts its connector gives it, as tabs', () => {
  const ids = (connector, instance) => instanceTabs(connector, instance).map((tab) => tab.id)
  // A connector that only has commands: its connection, and its keys when it signs in.
  assert.deepEqual(ids(CONNECTOR, { id: 'i1' }), ['connection', 'keys'])
  assert.deepEqual(ids({ ...CONNECTOR, native: true }, { id: 'i1' }), ['connection'])
  // One that fetches: how it fetches, its classifier and the mappers of its connector.
  const fetching = { ...CONNECTOR, fetch: { intervalSeconds: 120 } }
  assert.deepEqual(ids(fetching, { id: 'i1' }), ['connection', 'keys', 'fetch', 'classifier', 'mappers'])
  // A new instance has no classifier to edit yet: it is made first.
  assert.deepEqual(ids(fetching, null), ['connection', 'keys', 'fetch'])
  // One that mirrors and does not fetch has mappers and no classifier.
  assert.deepEqual(ids({ ...CONNECTOR, mirror: {} }, { id: 'i1' }), ['connection', 'keys', 'mappers'])
  // The tables take the width of the page.
  assert.deepEqual(
    instanceTabs(fetching, { id: 'i1' })
      .filter((tab) => tab.wide)
      .map((tab) => tab.id),
    ['classifier', 'mappers'],
  )
})

test('a list of hosts is shown one a line, and typing is left alone', async () => {
  const { hostLines } = await import('./instances.js')
  assert.equal(
    hostLines('files.vendor.example.com, *.storage.vendor.example.com'),
    'files.vendor.example.com\n*.storage.vendor.example.com',
  )
  assert.equal(hostLines('a.example.com;b.example.com'), 'a.example.com\nb.example.com')
  // Already one a line, with the line being typed still empty: nothing changes.
  assert.equal(hostLines('a.example.com\nb.example.com\n'), 'a.example.com\nb.example.com\n')
  assert.equal(hostLines('a.example.com,'), 'a.example.com\n')
  assert.equal(hostLines(''), '')
  assert.equal(hostLines(undefined), '')
})
