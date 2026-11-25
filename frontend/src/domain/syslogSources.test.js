import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  SYSLOG_MATTER_FILTER,
  SYSLOG_MATTER_TYPES,
  addressOf,
  channelLabel,
  expectedSyslog,
  logFamilies,
  matchSyslogSource,
  messageOf,
  programOf,
  syslogSourcesFor,
  syslogTitle,
  typeLabel,
} from './syslogSources.js'

test('Linux expects auth, journal and audit; macOS the unified log; no system, all of them', () => {
  assert.deepEqual(
    syslogSourcesFor('linux').map((item) => item.key),
    ['auth', 'journal', 'audit'],
  )
  assert.deepEqual(
    syslogSourcesFor('macos').map((item) => item.key),
    ['unifiedlog'],
  )
  assert.equal(syslogSourcesFor('').length, 4)
  assert.match(expectedSyslog('linux')[0].hint, /auth\.log/)
  assert.match(expectedSyslog('macos')[0].hint, /log show/)
  assert.deepEqual(Object.keys(expectedSyslog('linux')[0]).sort(), ['hint', 'key', 'label'])
})

test('a file is the expected source its name says', () => {
  assert.equal(matchSyslogSource({ source: 'linux.journal' }), 'journal')
  assert.equal(matchSyslogSource({ source: 'macos.unifiedlog' }), 'unifiedlog')
  assert.equal(matchSyslogSource({ source: 'windows.evtx' }), null)
  assert.equal(matchSyslogSource(null), null)
})

test('the page shows the logs of the system: Windows as it was, the others new, both without a system', () => {
  assert.deepEqual(logFamilies('windows'), { windows: true, syslog: false })
  assert.deepEqual(logFamilies('linux'), { windows: false, syslog: true })
  assert.deepEqual(logFamilies('macos'), { windows: false, syslog: true })
  assert.deepEqual(logFamilies(''), { windows: true, syslog: true })
  assert.equal(syslogTitle('linux'), 'Sources — Linux logs')
  assert.equal(syslogTitle(''), 'Sources — Linux and macOS logs')
})

test('"events that matter" are the types of a logon, a sudo, an account and a process', () => {
  assert.deepEqual(SYSLOG_MATTER_TYPES, ['logon', 'logon_failed', 'sudo', 'account', 'process'])
  assert.equal(SYSLOG_MATTER_FILTER, 'logon,logon_failed,sudo,account,process')
})

test('the cells read the data the worker writes', () => {
  assert.equal(typeLabel('logon_failed'), 'Failed logon')
  assert.equal(typeLabel('other'), 'other')
  assert.equal(channelLabel('unifiedlog'), 'unified log')
  const row = { summary: 'sum', data: { program: 'sshd', message: 'm', CommandLine: 'ls -l', source_ip: '10.0.0.1' } }
  assert.equal(messageOf(row), 'ls -l')
  assert.equal(messageOf({ summary: 's', data: { message: 'm' } }), 'm')
  assert.equal(messageOf({ summary: 's' }), 's')
  assert.equal(programOf(row), 'sshd')
  assert.equal(addressOf(row), '10.0.0.1')
  assert.equal(addressOf({}), '')
})
