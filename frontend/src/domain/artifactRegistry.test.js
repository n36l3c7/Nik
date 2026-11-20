import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  artifactIdFromPath,
  artifactMeta,
  artifactPath,
  artifactReference,
  kindForTab,
  parseTags,
  standaloneIncident,
  verdictBadge,
  ARTIFACTS_ROOT,
  isArtifactsPath,
} from './artifactRegistry.js'

const SHA = 'a'.repeat(64)
const file = {
  id: `file-${SHA}`,
  kind: 'file',
  ref: SHA,
  name: 'invoice.exe',
  verdict: 'high',
  score: null,
  detail: 'PE32 executable',
  size: 1024,
  tags: [],
  createdAt: '2026-11-11T10:00:00Z',
  createdBy: 'm.rossi',
  incidents: [],
}

test('only e-mails, files and captures become artifacts', () => {
  assert.equal(kindForTab('malware'), 'file')
  assert.equal(kindForTab('mail'), 'mail')
  assert.equal(kindForTab('network'), 'pcap')
  assert.equal(kindForTab('commands'), null)
  // An address is scanned, not uploaded.
  assert.equal(kindForTab('urls'), null)
})

test('the verdict badge never calls an undetected file clean', () => {
  assert.deepEqual(verdictBadge(file), { label: 'high', color: 'red' })
  assert.deepEqual(verdictBadge({ ...file, verdict: '' }), { label: 'no detection', color: 'slate' })
  assert.deepEqual(verdictBadge({ kind: 'mail', verdict: 'phishing', score: 85 }), {
    label: 'phishing · 85',
    color: 'red',
  })
  assert.equal(verdictBadge({ kind: 'pcap', verdict: '' }), null)
})

test('tags are lower case, valid, distinct and capped', () => {
  assert.deepEqual(parseTags('Emotet, campaign:q4 emotet; no! -bad'), ['emotet', 'campaign:q4'])
  assert.equal(parseTags(Array.from({ length: 20 }, (_, i) => `t${i}`).join(' ')).length, 12)
  assert.deepEqual(parseTags(''), [])
})

test('the permalink accepts only well-formed ids', () => {
  assert.equal(artifactIdFromPath(artifactPath(file.id)), file.id)
  assert.equal(artifactIdFromPath(`/artifact/pcap-${'b'.repeat(32)}`), `pcap-${'b'.repeat(32)}`)
  assert.equal(artifactIdFromPath(`/artifact/url-${'d'.repeat(32)}`), `url-${'d'.repeat(32)}`)
  assert.equal(artifactIdFromPath('/artifact/file-xyz'), null)
  assert.equal(artifactIdFromPath(`/artifact/file-${SHA}/../x`), null)
  assert.equal(artifactIdFromPath('/incident/abc'), null)
})

test('an artifact stands in for an incident that holds only it', () => {
  const incident = standaloneIncident(file)
  assert.equal(incident.id, null)
  assert.deepEqual(incident.flags, {})
  assert.deepEqual(incident.data.malware.samples, [artifactReference(file)])
  assert.equal(incident.data.malware.samples[0].fileName, 'invoice.exe')
  assert.deepEqual(incident.data.mail.messages, [])
  const capture = { ...file, kind: 'pcap', ref: 'c'.repeat(32), name: 'a.pcapng' }
  const live = { id: capture.ref, status: 'ready', packets: 67 }
  assert.deepEqual(standaloneIncident(capture, live).data.network.captures, [live])
})

test('the row tells the kind, the detail and where the artifact is linked', () => {
  assert.equal(artifactMeta(file), 'file · PE32 executable · m.rossi')
  assert.equal(
    artifactMeta({ ...file, incidents: [{ id: 'i1', name: 'INC-2041' }] }),
    'file · PE32 executable · INC-2041',
  )
  assert.equal(
    artifactMeta({ ...file, incidents: [{ id: 'i1' }, { id: 'i2' }] }),
    'file · PE32 executable · 2 incidents',
  )
})

test('a file is offered to be analysed as what the server says it can be', async () => {
  const { RELATION_LABELS, analyseAsActions } = await import('./artifactRegistry.js')
  assert.deepEqual(analyseAsActions({ kind: 'file', analyseAs: ['mail'] }), [
    { as: 'mail', label: 'Analyse as an e-mail', made: 'an e-mail' },
  ])
  assert.deepEqual(
    analyseAsActions({ kind: 'file', analyseAs: ['capture', 'something-new'] }).map((action) => action.label),
    ['Analyse as a capture'],
  )
  // Only a file, and only what the server offers.
  assert.deepEqual(analyseAsActions({ kind: 'mail', analyseAs: ['mail'] }), [])
  assert.deepEqual(analyseAsActions({ kind: 'file' }), [])
  assert.deepEqual(analyseAsActions(null), [])
  assert.equal(RELATION_LABELS.unpacked, 'unpacked file')
  assert.equal(RELATION_LABELS.analysed, 'analysis')
})

test('the page of the artifacts has an address of its own, which is not an artifact', () => {
  assert.equal(ARTIFACTS_ROOT, '/artifacts')
  assert.equal(isArtifactsPath('/artifacts'), true)
  assert.equal(isArtifactsPath('/artifacts/'), true)
  assert.equal(isArtifactsPath('/artifacts?x=1'), true)
  assert.equal(isArtifactsPath('/artifact/file-00'), false)
  assert.equal(isArtifactsPath('/'), false)
  assert.equal(artifactIdFromPath('/artifacts'), null)
})
