import test from 'node:test'
import assert from 'node:assert/strict'
import {
  chainStatus,
  forwardingBody,
  forwardingForm,
  forwardingProblem,
  forwardingStatus,
  isImported,
  originMark,
  levelOptions,
  parseHead,
  shortHash,
} from './auditChain.js'

const HASH = '9f2c'.repeat(16)
const ago = (iso) => `at ${iso}`

test('the chain says how far it holds, or where it broke', () => {
  assert.deepEqual(chainStatus(null), { color: 'slate', text: '', detail: '' })
  assert.equal(chainStatus({ verified: null, problem: null }).text, 'Not verified yet')
  const good = chainStatus(
    { verified: { seq: 4182, hash: HASH, at: 'T1' }, problem: null, fullWalk: { at: 'T0' }, unlinked: 0 },
    ago,
  )
  assert.deepEqual(good, {
    color: 'emerald',
    text: 'Holds up to entry 4182',
    detail: 'Verified at T1. Every entry was read at T0.',
  })
  assert.match(
    chainStatus({ verified: { seq: 3, at: 'T1' }, unlinked: 2 }, ago).detail,
    / 2 entries wait to be linked\.$/,
  )
  assert.equal(chainStatus({ verified: { seq: 0, at: 'T1' } }, ago).text, 'Holds: no entry yet')
  const broken = chainStatus(
    {
      verified: { seq: 4000, at: 'T1' },
      problem: {
        kind: 'edited',
        seq: 3120,
        text: 'The content of entry 3120 was changed after it was written',
        since: 'T2',
      },
    },
    ago,
  )
  assert.deepEqual(broken, {
    color: 'red',
    text: 'Broken at entry 3120',
    detail: 'The content of entry 3120 was changed after it was written. Found at T2.',
  })
})

test('an entry that came in a file from another server is told apart', () => {
  assert.equal(isImported({ origin: 'import' }), true)
  assert.equal(isImported({ origin: null }), false)
  assert.equal(isImported({}), false)
  assert.equal(isImported(null), false)
  assert.equal(originMark({ origin: 'import' }).text, 'imported')
  assert.equal(originMark({ origin: 'outside' }).text, 'written outside')
  assert.match(originMark({ origin: 'outside' }).note, /a restore leaves one such entry/)
  assert.equal(originMark({ origin: null }), null)
})

test('entries whose key the server no longer has are said, and are not a break', () => {
  const chain = {
    verified: { seq: 9, at: 'T1' },
    problem: null,
    unchecked: { 'derived-0a1b2c3d4e5f': 4, 'set-111122223333': 1 },
  }
  const status = chainStatus(chain, (iso) => `at ${iso}`)
  assert.equal(status.color, 'emerald')
  assert.match(
    status.detail,
    /The signature of 5 entries cannot be checked: this server no longer has the key derived-0a1b2c3d4e5f, set-111122223333\.$/,
  )
  assert.doesNotMatch(chainStatus({ verified: { seq: 9, at: 'T1' }, unchecked: {} }).detail, /cannot be checked/)
})

test('a head is typed as its number and its hash', () => {
  assert.equal(parseHead(''), null)
  assert.equal(parseHead('   '), null)
  assert.deepEqual(parseHead(`4182:${HASH}`), { seq: 4182, hash: HASH })
  assert.deepEqual(parseHead(` 4182 : ${HASH.toUpperCase()} `), { seq: 4182, hash: HASH })
  assert.deepEqual(parseHead(`4182 ${HASH}`), { seq: 4182, hash: HASH })
  for (const wrong of ['4182', HASH, `0:${HASH}`, `x:${HASH}`, `4182:${HASH.slice(1)}`, `4182:${HASH}00`]) {
    assert.ok(parseHead(wrong).error, wrong)
  }
  assert.equal(shortHash(HASH), '9f2c9f2c9f2c…')
  assert.equal(shortHash('nope'), '')
})

const SAVED = {
  enabled: true,
  host: 'siem.example',
  port: 6514,
  protocol: 'tls',
  ca: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
  verifyName: true,
  clientCert: '',
  clientKeySet: false,
  clientKeyCredential: '',
  facility: 13,
  severity: 5,
  appName: 'nik',
  hostname: 'nik',
  checkpointMinutes: 5,
  startFrom: 'beginning',
  maxDatagram: 2048,
}

test('the form of the forwarding starts from what is kept, and never holds the key', () => {
  const form = forwardingForm(SAVED)
  assert.equal(form.port, '6514')
  assert.equal(form.clientKey, '')
  assert.equal(forwardingProblem(form, SAVED), null)
  assert.deepEqual(forwardingBody(form), {
    enabled: true,
    host: 'siem.example',
    port: 6514,
    protocol: 'tls',
    facility: 13,
    severity: 5,
    appName: 'nik',
    hostname: 'nik',
    checkpointMinutes: 5,
    startFrom: 'beginning',
    ca: SAVED.ca.trim(),
    verifyName: true,
    clientCert: '',
  })
  // Nothing set yet: the defaults of the server's own.
  assert.deepEqual([forwardingForm().enabled, forwardingForm().port, forwardingForm().protocol], [false, '6514', 'tls'])
})

test('what cannot be saved is said before it is sent', () => {
  const form = forwardingForm(SAVED)
  const problem = (changes, settings = SAVED) => forwardingProblem({ ...form, ...changes }, settings)
  assert.equal(problem({ host: '' }), 'Name the receiver before turning the forwarding on.')
  assert.equal(problem({ host: '', enabled: false }), null)
  assert.equal(problem({ host: 'siem example' }), 'The receiver is a host name or an address.')
  assert.equal(problem({ port: '0' }), 'The port is a number from 1 to 65535.')
  assert.equal(problem({ port: 'syslog' }), 'The port is a number from 1 to 65535.')
  assert.equal(problem({ checkpointMinutes: '0' }), 'A checkpoint is sent every 1 to 1440 minutes.')
  assert.match(problem({ appName: 'two words' }), /^The application name is 1 to 48 printable/)
  assert.match(problem({ hostname: '' }), /^The host name is 1 to 255 printable/)
  assert.match(problem({ ca: 'MIIB…' }), /^The CA or certificate of the receiver is pasted in PEM/)
  const cert = '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----'
  assert.match(problem({ clientCert: cert }), /^A client certificate needs its key/)
  assert.equal(problem({ clientCert: cert, clientKey: '{{ credentials.syslog_key }}' }), null)
  // The key that is kept goes with the certificate that is kept.
  assert.equal(problem({ clientCert: cert }, { ...SAVED, clientCert: cert, clientKeySet: true }), null)
  // What belongs to another protocol is neither checked nor sent.
  assert.equal(problem({ protocol: 'tcp', ca: 'junk' }), null)
  assert.equal(problem({ protocol: 'udp', maxDatagram: '100' }), 'The largest datagram is 480 to 65000 bytes.')
  const udp = forwardingBody({ ...form, protocol: 'udp', port: '514', maxDatagram: '1024', clientKey: 'k' })
  assert.equal(udp.maxDatagram, 1024)
  assert.ok(!('ca' in udp) && !('clientKey' in udp) && !('verifyName' in udp))
  assert.equal(forwardingBody({ ...form, clientCert: cert, clientKey: 'KEY' }).clientKey, 'KEY')
})

test('facilities and severities are listed by their number', () => {
  assert.deepEqual(levelOptions({ notice: 5, emerg: 0, info: 6 }), [
    { value: '0', label: '0 · emerg' },
    { value: '5', label: '5 · notice' },
    { value: '6', label: '6 · info' },
  ])
})

const lasted = (seconds) => `${Math.round(seconds / 60)} minutes`
const state = (changes) => ({
  destination: 'tls://siem.example:6514',
  pendingChange: false,
  cursor: 4182,
  sent: 4182,
  sentAt: 'T1',
  error: '',
  errorSince: null,
  checkpointAt: 'T2',
  backlog: { entries: 0, oldestAt: null, seconds: 0 },
  sends: 'container',
  ...changes,
})

test('the forwarding says where the log goes, what waits and what is wrong', () => {
  const off = forwardingStatus({ settings: { enabled: false }, state: state({ destination: '' }) })
  assert.equal(off.text, 'Not forwarded')
  assert.match(off.detail, /^The log exists on this server only\./)
  const good = forwardingStatus({ settings: SAVED, state: state() }, ago, lasted)
  assert.deepEqual(good, {
    color: 'emerald',
    text: 'Sent to tls://siem.example:6514',
    detail: 'Nothing waits. 4182 sent, the last at T1. Last checkpoint at T2.',
  })
  const behind = forwardingStatus(
    { settings: SAVED, state: state({ backlog: { entries: 12, seconds: 180 } }) },
    ago,
    lasted,
  )
  assert.equal(behind.color, 'amber')
  assert.match(behind.detail, /^12 entries wait, the oldest for 3 minutes\. /)
  const down = forwardingStatus(
    {
      settings: SAVED,
      state: state({
        error: 'siem.example:6514 cannot be reached: Connection refused',
        errorSince: 'T3',
        backlog: { entries: 1, seconds: 0 },
        pendingChange: true,
      }),
    },
    ago,
    lasted,
  )
  assert.equal(down.color, 'red')
  assert.equal(down.text, 'Not arriving at tls://siem.example:6514')
  assert.equal(
    down.detail,
    'siem.example:6514 cannot be reached: Connection refused. Since at T3. 1 entry waits. They are sent in order ' +
      'when the receiver is back. The change that was saved takes effect once the receiver set before it has heard of it.',
  )
  const waiting = forwardingStatus({ settings: SAVED, state: state({ destination: '' }) }, ago, lasted)
  assert.equal(waiting.text, 'Turned on, not taken up yet')
  assert.match(
    forwardingStatus({ settings: SAVED, state: state({ destination: '', sends: 'off' }) }).detail,
    /which is off on this server/,
  )
})
