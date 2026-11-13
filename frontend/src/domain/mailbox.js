/*
 * Mailboxes (mbox, Maildir archive, Outlook PST): telling one from another
 * file, and laying out the graph of its conversations, in the way a
 * source-control tree is drawn.
 */

const ARCHIVE = /\.(zip|tar|tgz|tar\.gz)$/i

/**
 * Whether a dropped file is a mailbox, from its name and first bytes: an mbox
 * starts with "From ", a PST with "!BDN". An archive is one when its name
 * says so (maildir, mailbox) or, see `mailboxFormatOf`, when it holds the
 * folders of a Maildir: any other zip is a file to analyse.
 */
export function mailboxFormat({ name = '', head = new Uint8Array() } = {}) {
  const starts = (text) => text.split('').every((char, index) => head[index] === char.charCodeAt(0))
  if (/\.(eml|msg)$/i.test(name)) return null // one e-mail, even when it starts as an mbox does
  if (starts('!BDN')) return 'pst'
  if (starts('From ')) return 'mbox'
  if (ARCHIVE.test(name) && /maildir|mailbox/i.test(name)) return 'maildir'
  return null
}

/**
 * Whether the bytes of an archive (a zip directory, tar headers) name the
 * messages of a Maildir: a file in a `cur/` folder, or one in `new/` named
 * as a Maildir names them (it starts with the time of delivery).
 */
export function holdsMaildir(bytes) {
  let text = ''
  for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192))
  return /(^|[/\0])cur\/[^/\0]/.test(text) || /(^|[/\0])new\/\d{9,}\./.test(text)
}

const SNIFF_BYTES = 512 * 1024

async function gunzipStart(blob, limit = 2 * SNIFF_BYTES) {
  // The start of a gzip, as far as the slice goes: its end is cut, which
  // ends the reading with an error after the bytes that could be read.
  const chunks = []
  let size = 0
  try {
    const reader = blob.stream().pipeThrough(new DecompressionStream('gzip')).getReader()
    while (size < limit) {
      const { done, value } = await reader.read()
      if (done) break
      chunks.push(value)
      size += value.length
    }
    reader.cancel().catch(() => {})
  } catch {
    // Cut short: what was read is enough.
  }
  const out = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) {
    out.set(chunk, at)
    at += chunk.length
  }
  return out
}

/**
 * `mailboxFormat`, and for an archive with any name a look inside: the
 * directory at the end of a zip, the first headers of a tar (gzipped or
 * not). Only a slice of the file is read, whatever its size.
 */
export async function mailboxFormatOf(file, head) {
  const format = mailboxFormat({ name: file.name, head })
  if (format) return format
  const zip = head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04
  const gzip = head[0] === 0x1f && head[1] === 0x8b
  const tar = /\.tar$/i.test(file.name)
  if (!zip && !gzip && !tar) return null
  try {
    const start = file.slice(0, SNIFF_BYTES)
    if (gzip) return holdsMaildir(await gunzipStart(start)) ? 'maildir' : null
    if (holdsMaildir(new Uint8Array(await start.arrayBuffer()))) return 'maildir'
    if (zip && file.size > SNIFF_BYTES) {
      const end = new Uint8Array(await file.slice(file.size - SNIFF_BYTES).arrayBuffer())
      if (holdsMaildir(end)) return 'maildir'
    }
  } catch {
    // Unreadable: not a mailbox we can tell.
  }
  return null
}

export const MAILBOX_FORMATS = { mbox: 'mbox', maildir: 'Maildir archive', pst: 'Outlook PST' }

/** Colours of the conversations (the lines and nodes of one thread share one). */
export const THREAD_COLOURS = ['#f85149', '#58a6ff', '#d2a8ff', '#3fb950', '#e3b341', '#ff9bce', '#79c0ff', '#ffa657']

export const threadColour = (thread) => THREAD_COLOURS[Math.abs(Number(thread) || 0) % THREAD_COLOURS.length]

export const MAX_LANES = 10

/**
 * Lay out the messages (newest first, as listed) as a graph: each gets a lane,
 * and an edge to the message it answers when that one is listed too.
 *
 * A message takes the lane of the first reply that was waiting for it, so a
 * conversation runs down one lane; other replies to the same message come in
 * from their own lanes (a fork: a forward, an answer from someone else).
 * Returns `{ lanes, nodes: [{ seq, lane, row }], edges: [{ from, to,
 * fromLane, toLane, thread }] }` with `from` and `to` as row numbers.
 */
export function layoutGraph(messages = []) {
  const rowOf = new Map(messages.map((message, row) => [message.seq, row]))
  const waiting = [] // lane -> the seq a reply above is waiting for, or null
  const nodes = []
  const edges = []
  let lanes = 0
  messages.forEach((message, row) => {
    const mine = waiting.map((seq, lane) => (seq === message.seq ? lane : -1)).filter((lane) => lane >= 0)
    let lane = mine.length ? mine[0] : waiting.findIndex((seq) => seq === null || seq === undefined)
    if (lane < 0) lane = Math.min(waiting.length, MAX_LANES - 1)
    for (const other of mine) waiting[other] = null
    const parentListed = message.parent !== null && message.parent !== undefined && rowOf.get(message.parent) > row
    waiting[lane] = parentListed ? message.parent : null
    nodes.push({ seq: message.seq, lane, row })
    lanes = Math.max(lanes, lane + 1)
  })
  const laneOf = new Map(nodes.map((node) => [node.seq, node.lane]))
  messages.forEach((message, row) => {
    const to = rowOf.get(message.parent)
    if (to === undefined || to <= row) return
    edges.push({
      from: row,
      to,
      fromLane: laneOf.get(message.seq),
      toLane: laneOf.get(message.parent),
      thread: message.thread,
    })
  })
  return { lanes: Math.max(lanes, 1), nodes, edges }
}

/** The SVG path of an edge: down the reply's lane, then across to the message it answers. */
export function edgePath(edge, { rowHeight, laneWidth, inset }) {
  const x1 = inset + edge.fromLane * laneWidth
  const x2 = inset + edge.toLane * laneWidth
  const y1 = edge.from * rowHeight + rowHeight / 2
  const y2 = edge.to * rowHeight + rowHeight / 2
  if (x1 === x2) return `M${x1},${y1} L${x2},${y2}`
  const bend = y2 - rowHeight / 2
  return `M${x1},${y1} L${x1},${bend - 4} C${x1},${bend + 6} ${x2},${bend - 4} ${x2},${y2}`
}

/** "3 Mar – 12 Nov 2026" from two Unix times in milliseconds. */
export function dateRange(from, to) {
  if (!from || !to) return ''
  const day = (ms, year) =>
    new Date(ms).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      ...(year ? { year: 'numeric' } : {}),
      timeZone: 'UTC',
    })
  const sameYear = new Date(from).getUTCFullYear() === new Date(to).getUTCFullYear()
  return `${day(from, !sameYear)} – ${day(to, true)}`
}

/** A date input's value (YYYY-MM-DD) as Unix milliseconds: the start of the day, or its end. */
export function dayToMs(value, endOfDay = false) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value ?? ''))) return null
  const ms = Date.parse(`${value}T00:00:00Z`)
  return Number.isNaN(ms) ? null : ms + (endOfDay ? 86_399_999 : 0)
}

/** What an import would do, in a sentence. */
export function planLine(plan) {
  if (!plan) return ''
  const parts = [`${plan.matches} ${plan.matches === 1 ? 'message matches' : 'messages match'}`]
  if (plan.withConversations > plan.matches) parts.push(`${plan.withConversations} with their conversations`)
  if (plan.alreadyInNik) parts.push(`${plan.alreadyInNik} already in Nik`)
  if (plan.tooLarge) parts.push(`${plan.tooLarge} too large`)
  if (plan.waiting) parts.push(`${plan.waiting} over the limit of ${plan.max}, left for the next time`)
  return `${parts.join(' · ')}.`
}
