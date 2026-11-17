/**
 * Generate a RFC-4122 version-4 UUID (for incidents and imported rows).
 *
 * Prefers `crypto.randomUUID()` (a v4 UUID), but that API requires a secure
 * context, so on plain HTTP over a LAN IP it is undefined. There we build a v4
 * from `crypto.getRandomValues` (available in insecure contexts too). There
 * is no fallback on `Math.random`: an id is never made from a guessable source.
 */
export function generateId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }

  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = crypto.getRandomValues(new Uint8Array(16))
    bytes[6] = (bytes[6] & 0x0f) | 0x40 // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80 // variant 10xx
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'))
    return (
      hex.slice(0, 4).join('') +
      '-' +
      hex.slice(4, 6).join('') +
      '-' +
      hex.slice(6, 8).join('') +
      '-' +
      hex.slice(8, 10).join('') +
      '-' +
      hex.slice(10, 16).join('')
    )
  }

  // Every browser Nik runs in has one of the two: an id is never made from a guessable source.
  throw new Error('This browser cannot make a random id: it has no crypto API.')
}
