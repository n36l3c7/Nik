/** Save a Blob as a file the browser downloads. */
export function saveBlob(blob, fileName) {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/**
 * Save what an address serves, by an anchor on it: the browser streams the file to the disk, so a large
 * zip is not held in memory (the session cookie goes with the request; a refusal shows as a failed download).
 */
export function saveUrl(url, fileName = '') {
  const anchor = document.createElement('a')
  anchor.href = url
  if (fileName) anchor.download = fileName
  anchor.rel = 'noopener'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
}

/**
 * Copy text; false when the browser refuses.
 *
 * The clipboard of a page exists only where the page is served over HTTPS (or from the
 * machine itself): on a server reached over plain HTTP `navigator.clipboard` is not there at
 * all. The text is then copied the older way, through a field that is selected and copied.
 */
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return copyThroughField(text)
  }
}

function copyThroughField(text) {
  if (typeof document === 'undefined' || typeof document.execCommand !== 'function') return false
  const field = document.createElement('textarea')
  field.value = text
  field.setAttribute('readonly', '')
  field.setAttribute('aria-hidden', 'true')
  field.style.position = 'fixed'
  field.style.top = '0'
  field.style.left = '-9999px'
  const focused = document.activeElement
  document.body.appendChild(field)
  field.select()
  let done
  try {
    done = document.execCommand('copy')
  } catch {
    done = false
  }
  field.remove()
  focused?.focus?.()
  return done
}
