import assert from 'node:assert/strict'
import { test } from 'node:test'
import { authOf, fieldsOf, formProblem, payloadOf, problemLines, startingValues } from './connections.js'

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
  assert.deepEqual(fieldsOf(null), [])
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
