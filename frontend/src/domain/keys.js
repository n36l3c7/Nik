/*
 * The keys of the server and the encryption of the store, as
 * GET /api/system/keys and GET /api/storage/encryption answer: what to show.
 *
 * Nothing here ever holds the value of a key: the server does not send one.
 * A key is told from another by its fingerprint, a few characters that are
 * not a part of it.
 */

/** "2 hours 5 minutes", "40 seconds": how long, in words. */
export function durationWords(seconds) {
  const whole = Math.max(0, Math.round(Number(seconds) || 0))
  if (whole < 60) return `${whole} second${whole === 1 ? '' : 's'}`
  const minutes = Math.round(whole / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'}`
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  const words = `${hours} hour${hours === 1 ? '' : 's'}`
  return rest ? `${words} ${rest} minute${rest === 1 ? '' : 's'}` : words
}

/** Where a key comes from: `{ text, color, detail }` for its badge and the line under it. */
export function sourceText(key) {
  if (key?.source === 'file') {
    return { text: 'a file', color: 'emerald', detail: 'Mounted into the containers that use it, and no other.' }
  }
  if (key?.source === 'environment') {
    return {
      text: 'the environment',
      color: 'amber',
      detail: 'In .env: whoever can inspect a container of the stack reads it.',
    }
  }
  if (key?.derived) {
    // The audit key of a server that was given none: made from the secret key, wherever that one is.
    return {
      text: 'the secret key, derived',
      color: 'slate',
      detail: 'No key of its own was given to the server: the audit log is signed with one made from the secret key.',
    }
  }
  return { text: 'not set', color: 'slate', detail: '' }
}

/** Where a change of key stands: `{ text, color, detail }`. */
export function rotationStatus(rotation) {
  const state = rotation?.state ?? 'idle'
  const total = Number(rotation?.total) || 0
  const done = Math.min(total, Number(rotation?.done) || 0)
  if (state === 'running') {
    return {
      text: 'being changed',
      color: 'amber',
      detail: total
        ? `${done} of ${total} under the new key. The server holds both keys until all of it is read back.`
        : 'The server holds both keys until everything is under the new one and was read back.',
    }
  }
  if (state === 'failed') {
    const failed = rotation?.failed ?? []
    return {
      text: 'not finished',
      color: 'red',
      detail: failed.length
        ? `${failed.length} could not be put under the new key (the first: ${failed[0].name}: ${failed[0].reason}). Keep the earlier key where it is.`
        : 'Something could not be put under the new key. Keep the earlier key where it is.',
    }
  }
  if (state === 'verified') {
    return {
      text: 'verified',
      color: 'emerald',
      detail: 'Everything is under the new key and was read back with it alone. The earlier key can go.',
    }
  }
  return { text: '', color: 'slate', detail: '' }
}

/** Whether the page is read again by itself: while a change of key is in progress. */
export const rotating = (keys) => (keys ?? []).some((key) => key.rotation?.state === 'running')

/** How much of a rotation is done, 0 to 100; null when nothing is counted yet. */
export function rotationPercent(rotation) {
  const total = Number(rotation?.total) || 0
  if (!total) return null
  return Math.max(0, Math.min(100, Math.round(((Number(rotation?.done) || 0) / total) * 100)))
}

/**
 * The state of the encryption of the store: `{ title, color, lines, percent, working }`.
 * `formatBytes` and `formatDate` turn numbers and times into words; `percent` is null
 * when there is nothing to draw a bar of.
 */
export function encryptionStatus(status, formatBytes, formatDate) {
  const state = status?.state ?? 'starting'
  const total = status?.total ?? { files: 0, bytes: 0 }
  const done = status?.done ?? { files: 0, bytes: 0 }
  const left = status?.left ?? { files: 0, bytes: 0 }
  const percent = total.bytes > 0 ? Math.max(0, Math.min(100, Math.floor((done.bytes / total.bytes) * 100))) : null
  if (state === 'sealed') {
    const lines = [`Every file of the store is encrypted${status.since ? ` since ${formatDate(status.since)}` : ''}.`]
    const converted = status.converted
    if (converted?.files) {
      lines.push(
        `${converted.files} file${converted.files === 1 ? '' : 's'} from before 6.8 (${formatBytes(converted.bytes)}) ` +
          `were encrypted in ${durationWords(converted.seconds)}.`,
      )
    }
    return { title: 'Encrypted', color: 'emerald', lines, percent: null, working: false }
  }
  if (state === 'starting') {
    return {
      title: 'Looking at the store',
      color: 'slate',
      lines: ['The server is counting the files that are not encrypted yet. New files are encrypted already.'],
      percent: null,
      working: true,
    }
  }
  const lines = [
    `${done.files} of ${total.files} files from before 6.8 are encrypted (${formatBytes(done.bytes)} of ${formatBytes(total.bytes)}). ` +
      'New files are encrypted as they arrive.',
  ]
  if (state === 'paused') {
    lines.push(
      `Paused${status.pausedBy ? ` by ${status.pausedBy}` : ''}: ${left.files} file${left.files === 1 ? '' : 's'} (${formatBytes(left.bytes)}) are still in clear on the disk.`,
    )
    return { title: 'Paused', color: 'amber', lines, percent, working: false }
  }
  if (status?.secondsLeft != null && left.bytes > 0) {
    lines.push(`About ${durationWords(status.secondsLeft)} left, at ${formatBytes(status.bytesPerSecond)} a second.`)
  }
  if (status?.stuckCount) {
    lines.push(
      `${status.stuckCount} file${status.stuckCount === 1 ? '' : 's'} could not be encrypted and ${status.stuckCount === 1 ? 'is' : 'are'} still in clear: the server tries again by itself.`,
    )
    return { title: 'Stuck', color: 'red', lines, percent, working: true }
  }
  return { title: 'Encrypting', color: 'amber', lines, percent, working: true }
}

/** What the dialog of a change of key lists: "12 credentials", in the order the server gave. */
export function planLines(plan) {
  return (plan?.items ?? []).filter((item) => item.count > 0).map((item) => `${item.count} × ${item.what}`)
}

/** The sentence that says which containers stop for a moment. */
export function restartText(plan) {
  const services = plan?.restarts ?? []
  if (!services.length) return ''
  const names = services.length === 1 ? services[0] : `${services.slice(0, -1).join(', ')} and ${services.at(-1)}`
  return (
    `The ${services.length === 1 ? 'container' : 'containers'} ${names} ${services.length === 1 ? 'restarts' : 'restart'} twice, ` +
    'about a minute each time: once to take the new key, once to forget the earlier one. Nik does not answer meanwhile.'
  )
}

/** The sentence for a key whose change restarts its containers once (the audit key). */
export function restartOnceText(plan) {
  const services = plan?.restarts ?? []
  if (!services.length) return ''
  const names = services.length === 1 ? services[0] : `${services.slice(0, -1).join(', ')} and ${services.at(-1)}`
  return (
    `The ${services.length === 1 ? 'container' : 'containers'} ${names} ${services.length === 1 ? 'restarts' : 'restart'} once, ` +
    'about a minute, to take the new key. Nik does not answer meanwhile.'
  )
}

/**
 * What the audit key signed: `{ lines, problem }`. One line for each key that signed entries
 * (by its id, which is not a part of it), and a sentence when entries cannot be checked
 * because the server no longer holds the key that signed them.
 */
export function auditSignedLines(signed) {
  const entries = (count) => `${count} ${count === 1 ? 'entry' : 'entries'}`
  const lines = (signed?.byKey ?? []).map(
    (key) =>
      `${key.keyId}: ${entries(key.entries)}` +
      (key.current
        ? ', the key in use'
        : key.known
          ? ', an earlier key the server still holds'
          : ', a key the server no longer holds'),
  )
  if (signed?.unsigned) lines.push(`${entries(signed.unsigned)} without a signature`)
  const lost = Number(signed?.cannotBeChecked) || 0
  const problem = lost
    ? `${entries(lost)} of the audit log cannot be checked: the key that signed ${lost === 1 ? 'it' : 'them'} is not among ` +
      'the keys of this server. Their place in the chain still is. Put the key back into AUDIT_KEY_PREVIOUS if you have it.'
    : ''
  return { lines, problem }
}
