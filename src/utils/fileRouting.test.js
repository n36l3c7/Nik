import test from 'node:test'
import assert from 'node:assert/strict'
import { detectFileRoute } from './fileRouting.js'

const bytes = (...parts) =>
  new Uint8Array(parts.flatMap((p) => (typeof p === 'string' ? [...p].map((c) => c.charCodeAt(0)) : p)))
const route = (name, head) => detectFileRoute({ name, head })

test('executables are recognised by their header, not their name', () => {
  assert.equal(route('invoice.pdf', bytes('MZ', [0x90, 0])).tab, 'malware')
  assert.match(route('invoice.pdf', bytes('MZ', [0x90, 0])).label, /PE/)
  assert.equal(route('a', bytes([0x7f], 'ELF')).label, 'Linux executable (ELF)')
  assert.equal(route('a', bytes([0xcf, 0xfa, 0xed, 0xfe])).label, 'macOS executable (Mach-O)')
  assert.equal(route('Fattura.pdf.docm', bytes('PK', [3, 4])).tab, 'malware')
  assert.equal(route('notes.txt', bytes('hello')), null)
})

test('forensic artifacts go to their tab and source', () => {
  assert.deepEqual(route('Security.evtx', bytes('ElfFile', [0])).params, { kind: 'evtx' })
  assert.deepEqual(route('History', bytes('SQLite format 3', [0])).params, { engine: 'chromium', source: 'history' })
  assert.equal(route('places.sqlite', bytes('SQLite format 3', [0])).params.browser, 'firefox')
  assert.equal(route('Downloads.plist', bytes('bplist00')).params.source, 'downloads')
  assert.equal(route('Bookmarks', bytes('{"roots"')).params.source, 'bookmarks')
  assert.deepEqual(route('.bash_history', bytes('ls')).params, { shell: 'bash' })
  assert.deepEqual(route('ConsoleHost_history.txt', bytes('dir')).params, { shell: 'powershell' })
  assert.deepEqual(route('host.json', bytes('{"format":"nik-eventlogs"')).params, { kind: 'json' })
  assert.equal(route('autoruns.csv', bytes('name,path')).tab, 'endpoint')
})
