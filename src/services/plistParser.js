/*
 * ============================================================================
 * PROPERTY LIST PARSER — Apple binary (bplist00) and XML plists
 * ============================================================================
 *
 * macOS stores many artifacts as property lists (Safari's Downloads.plist and
 * Bookmarks.plist among them), usually in the BINARY format. This module
 * decodes both formats in the analyst's browser, with no dependency:
 *
 *   parsePlist(arrayBuffer) → plain JS value
 *
 * Type mapping: dict → object, array/set → array, string → string,
 * integer/real → number (64-bit integers beyond 2^53 become BigInt), boolean →
 * boolean, date → Date, data → Uint8Array, UID (NSKeyedArchiver) → { UID: n }.
 *
 * Binary layout (CoreFoundation `CFBinaryPList.c`): an 8-byte header
 * "bplist00", the objects, an offset table, and a 32-byte trailer giving the
 * integer sizes, the object count, the top object and the table position.
 */

import { MAC_EPOCH_OFFSET_S } from '../utils/time.js'

const BPLIST_MAGIC = 'bplist00'
const TRAILER_SIZE = 32
const MAX_DEPTH = 512

/** True if the buffer starts with the binary plist header "bplist00". */
export function isBinaryPlist(arrayBuffer) {
  if (!arrayBuffer || arrayBuffer.byteLength < BPLIST_MAGIC.length + TRAILER_SIZE) return false
  const bytes = new Uint8Array(arrayBuffer, 0, BPLIST_MAGIC.length)
  for (let i = 0; i < BPLIST_MAGIC.length; i++) {
    if (bytes[i] !== BPLIST_MAGIC.charCodeAt(i)) return false
  }
  return true
}

/** True if the text looks like an XML property list. */
export function looksLikeXmlPlist(text) {
  const head = String(text ?? '').replace(/^﻿/, '').trimStart().slice(0, 512)
  return head.startsWith('<?xml') ? head.includes('<plist') || head.includes('PropertyList') : head.startsWith('<plist')
}

/**
 * Decodes a binary or XML property list.
 * @param {ArrayBuffer} arrayBuffer the file content
 * @returns {*} the decoded top-level object
 * @throws {Error} on a malformed file, with a message for the analyst
 */
export function parsePlist(arrayBuffer) {
  if (isBinaryPlist(arrayBuffer)) return parseBinaryPlist(arrayBuffer)
  const text = new TextDecoder('utf-8').decode(arrayBuffer)
  if (looksLikeXmlPlist(text)) return parseXmlPlist(text)
  throw new Error('Not a property list: expected a binary (bplist00) or XML plist.')
}

/* ------------------------------------------------------------------------ */
/* Binary format                                                              */
/* ------------------------------------------------------------------------ */

function corrupted(detail) {
  return new Error(`Corrupted binary plist (${detail}).`)
}

/** Big-endian unsigned integer of 1–8 bytes (BigInt beyond 2^53). */
function readUInt(view, pos, size) {
  if (pos < 0 || pos + size > view.byteLength) throw corrupted('read out of bounds')
  let value = 0n
  for (let i = 0; i < size; i++) value = (value << 8n) | BigInt(view.getUint8(pos + i))
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value
}

function toIndex(value, what) {
  if (typeof value !== 'number') throw corrupted(`${what} too large`)
  return value
}

export function parseBinaryPlist(arrayBuffer) {
  const view = new DataView(arrayBuffer)
  const trailer = arrayBuffer.byteLength - TRAILER_SIZE
  const offsetSize = view.getUint8(trailer + 6)
  const refSize = view.getUint8(trailer + 7)
  const numObjects = toIndex(readUInt(view, trailer + 8, 8), 'object count')
  const topObject = toIndex(readUInt(view, trailer + 16, 8), 'top object')
  const tableOffset = toIndex(readUInt(view, trailer + 24, 8), 'offset table')

  if (offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8) {
    throw corrupted('invalid integer sizes')
  }
  if (topObject >= numObjects || tableOffset + numObjects * offsetSize > trailer) {
    throw corrupted('invalid trailer')
  }

  const offsetOf = (ref) => {
    if (ref >= numObjects) throw corrupted('object reference out of range')
    return toIndex(readUInt(view, tableOffset + ref * offsetSize, offsetSize), 'object offset')
  }

  // Length of a container/string: inline nibble, or a following int object.
  const readLength = (pos, info) => {
    if (info !== 0x0f) return { length: info, start: pos + 1 }
    const marker = view.getUint8(pos + 1)
    if (marker >> 4 !== 0x1) throw corrupted('invalid length marker')
    const size = 1 << (marker & 0x0f)
    const length = toIndex(readUInt(view, pos + 2, size), 'length')
    return { length, start: pos + 2 + size }
  }

  const readRefs = (start, count) => {
    if (start + count * refSize > tableOffset) throw corrupted('reference list out of bounds')
    const refs = []
    for (let i = 0; i < count; i++) refs.push(toIndex(readUInt(view, start + i * refSize, refSize), 'reference'))
    return refs
  }

  const bytesAt = (start, length) => {
    if (start + length > tableOffset) throw corrupted('value out of bounds')
    return new Uint8Array(arrayBuffer, start, length)
  }

  const parseObject = (ref, stack) => {
    if (stack.length > MAX_DEPTH) throw corrupted('nesting too deep')
    if (stack.includes(ref)) throw corrupted('reference cycle')
    const pos = offsetOf(ref)
    if (pos >= tableOffset) throw corrupted('object offset out of bounds')
    const marker = view.getUint8(pos)
    const type = marker >> 4
    const info = marker & 0x0f

    switch (type) {
      case 0x0:
        if (info === 0x8) return false
        if (info === 0x9) return true
        return null // 0x00 null, 0x0F fill
      case 0x1: {
        const size = 1 << info
        if (size === 16) return Number(BigInt.asIntN(64, BigInt(readUInt(view, pos + 9, 8))))
        if (size === 8) {
          const value = BigInt.asIntN(64, BigInt(readUInt(view, pos + 1, 8)))
          const safe = value <= BigInt(Number.MAX_SAFE_INTEGER) && value >= BigInt(Number.MIN_SAFE_INTEGER)
          return safe ? Number(value) : value
        }
        if (size > 8) throw corrupted('invalid integer size')
        return readUInt(view, pos + 1, size)
      }
      case 0x2:
        if (info === 2) return view.getFloat32(pos + 1)
        if (info === 3) return view.getFloat64(pos + 1)
        throw corrupted('invalid real size')
      case 0x3:
        if (info !== 3) throw corrupted('invalid date')
        return new Date((view.getFloat64(pos + 1) + MAC_EPOCH_OFFSET_S) * 1000)
      case 0x4: {
        const { length, start } = readLength(pos, info)
        return bytesAt(start, length).slice()
      }
      case 0x5: {
        const { length, start } = readLength(pos, info)
        return new TextDecoder('latin1').decode(bytesAt(start, length))
      }
      case 0x6: {
        const { length, start } = readLength(pos, info)
        return new TextDecoder('utf-16be').decode(bytesAt(start, length * 2))
      }
      case 0x8:
        return { UID: readUInt(view, pos + 1, info + 1) }
      case 0xa:
      case 0xc: {
        const { length, start } = readLength(pos, info)
        const next = [...stack, ref]
        return readRefs(start, length).map((child) => parseObject(child, next))
      }
      case 0xd: {
        const { length, start } = readLength(pos, info)
        const keys = readRefs(start, length)
        const values = readRefs(start + length * refSize, length)
        const next = [...stack, ref]
        const dict = {}
        keys.forEach((keyRef, i) => {
          const key = parseObject(keyRef, next)
          if (typeof key !== 'string') throw corrupted('non-string dictionary key')
          dict[key] = parseObject(values[i], next)
        })
        return dict
      }
      default:
        throw corrupted(`unknown object type 0x${marker.toString(16)}`)
    }
  }

  return parseObject(topObject, [])
}

/* ------------------------------------------------------------------------ */
/* XML format (e.g. after `plutil -convert xml1`)                             */
/* ------------------------------------------------------------------------ */

function base64ToBytes(text) {
  const binary = atob(text.replace(/\s+/g, ''))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function xmlValue(node) {
  switch (node.tagName) {
    case 'dict': {
      const dict = {}
      const children = [...node.children]
      for (let i = 0; i < children.length; i += 2) {
        if (children[i].tagName !== 'key' || !children[i + 1]) {
          throw new Error('Malformed XML plist: <dict> entries must be <key>/value pairs.')
        }
        dict[children[i].textContent] = xmlValue(children[i + 1])
      }
      return dict
    }
    case 'array':
      return [...node.children].map(xmlValue)
    case 'string':
      return node.textContent
    case 'integer':
    case 'real':
      return Number(node.textContent)
    case 'true':
      return true
    case 'false':
      return false
    case 'date':
      return new Date(node.textContent.trim())
    case 'data':
      return base64ToBytes(node.textContent)
    default:
      throw new Error(`Malformed XML plist: unexpected <${node.tagName}>.`)
  }
}

export function parseXmlPlist(text) {
  if (typeof DOMParser === 'undefined') throw new Error('XML plists can only be parsed in a browser.')
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  if (doc.querySelector('parsererror')) throw new Error('Malformed XML plist.')
  const root = doc.documentElement
  if (root?.tagName !== 'plist' || !root.firstElementChild) {
    throw new Error('Malformed XML plist: missing <plist> root value.')
  }
  return xmlValue(root.firstElementChild)
}
