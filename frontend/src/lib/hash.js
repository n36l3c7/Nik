/**
 * SHA-256 of a File/Blob as lowercase hex, computed in the browser for the
 * evidence record of an imported artifact (the file itself never leaves the
 * analyst's machine). Empty string when Web Crypto is unavailable (an insecure
 * context): the import still works, without the digest.
 */
export async function sha256Hex(blob) {
  if (!globalThis.crypto?.subtle || !blob?.arrayBuffer) return ''
  try {
    const digest = await globalThis.crypto.subtle.digest('SHA-256', await blob.arrayBuffer())
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
  } catch {
    return ''
  }
}
