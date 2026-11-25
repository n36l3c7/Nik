import test from 'node:test'
import assert from 'node:assert/strict'
import { HOST_TAB, detectFileRoute } from './fileRouting.js'

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

test('files of host evidence go to the server to be recognised, not to a guessed tab', () => {
  const host = (name, head) => assert.equal(route(name, head)?.tab, HOST_TAB, name)
  host('Security.evtx', bytes('ElfFile', [0]))
  host('History', bytes('SQLite format 3', [0]))
  host('places.sqlite', bytes('SQLite format 3', [0]))
  host('Downloads.plist', bytes('bplist00'))
  host('Bookmarks', bytes('{"roots"'))
  host('.bash_history', bytes('ls'))
  host('ConsoleHost_history.txt', bytes('dir'))
  host('host.json', bytes('{"format":"nik-eventlogs"'))
  host('autoruns.csv', bytes('name,path'))
})

test('the files 7.0 reads are host evidence by their name', () => {
  const names = ['SYSTEM', 'NTUSER.DAT', 'Amcache.hve', 'SRUDB.dat', 'CMD.EXE-0BD30981.pf', '$MFT', '$J', 'auth.log']
  for (const name of [...names, 'secure.1']) assert.equal(route(name, bytes('regf'))?.tab, HOST_TAB, name)
  assert.equal(route('1b4dd67f.automaticDestinations-ms', bytes(''))?.tab, HOST_TAB)
  assert.equal(route('plaso.jsonl', bytes('{'))?.tab, HOST_TAB)
  // A disk image is sent too: the server says how to turn it into something Nik reads.
  assert.equal(route('disk.vhdx', bytes('vhdxfile'))?.tab, HOST_TAB)
  assert.equal(route('x.plaso', bytes('SQLite'))?.tab, HOST_TAB)
})

test('a zip and a shortcut dropped outside a host-evidence page stay samples, as in 6.x', () => {
  assert.equal(route('evidence.zip', bytes('PK', [3, 4]))?.tab, 'malware')
  assert.equal(route('invoice.zip', bytes('PK', [3, 4]))?.tab, 'malware')
  assert.equal(route('a.lnk', bytes('L', [0, 0, 0]))?.tab, 'malware')
  // A disk image is still sent: the server says what to do with it.
  for (const name of ['d.vhd', 'd.vhdx', 'd.vmdk', 'd.e01']) assert.equal(route(name, bytes('x'))?.tab, HOST_TAB, name)
})

test('a program with a name of host evidence is still a program', () => {
  assert.equal(route('SYSTEM', bytes('MZ', [0x90, 0]))?.tab, 'malware')
})

test('e-mails go to Mail Analysis; other OLE files stay samples', () => {
  const ole = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]
  assert.equal(route('Reset password.msg', bytes(ole)).tab, 'mail')
  assert.equal(route('Invoice.doc', bytes(ole)).tab, 'malware')
  assert.equal(route('phish.eml', bytes('Received: from x')).tab, 'mail')
  assert.equal(route('message', bytes('Return-Path: <a@b.c>')).tab, 'mail')
  assert.equal(route('notes', bytes('hello')), null)
})

test('packet captures go to Network Analysis', () => {
  assert.equal(route('capture.pcapng', bytes([0x0a, 0x0d, 0x0d, 0x0a])).tab, 'network')
  assert.equal(route('dump', bytes([0xd4, 0xc3, 0xb2, 0xa1])).label, 'Packet capture (pcap)')
  assert.equal(route('trace.pcap.gz', bytes([0x1f, 0x8b, 8])).tab, 'network')
  assert.equal(route('other.gz', bytes([0x1f, 0x8b, 8])).tab, 'malware')
})
