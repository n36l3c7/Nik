/** Extracts the file name from a Windows/Unix path or from a file:// URI. */
export function fileNameFromPath(path) {
  if (!path) return ''
  let value = String(path)
  if (value.startsWith('file:')) {
    try {
      value = decodeURIComponent(value.replace(/^file:\/*/i, ''))
    } catch {
      /* leave the raw value */
    }
  }
  value = value.split(/[?#]/)[0] // remove any query/fragment
  const parts = value.split(/[\\/]/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : value
}
