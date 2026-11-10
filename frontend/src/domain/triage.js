/*
 * ============================================================================
 * FUNCTION TRIAGE (Code view) — what is library, what uses which strings,
 * where to start
 * ============================================================================
 *
 * Pure helpers over the analyzer worker's facts:
 *  - `classifyFunction`: library (FLIRT signature, or the Rust crate its panic
 *    paths name), compiler runtime (by name), thunk / fragment, or unknown.
 *    "Unknown" is not "the author's code": in release builds much library
 *    code carries no tell-tale, so the UI says "not recognised".
 *  - `linkStrings`: the strings and indicators each function references (the
 *    worker reports file offsets; the analysis has the string texts).
 *  - `startHere`: the unrecognised functions most worth reading first.
 */

import { displayName } from './code.js'

/** Origins of a function, in the order the UI lists them. */
export const ORIGINS = {
  unknown: { label: 'not recognised', color: 'slate' },
  library: { label: 'library', color: 'cyan' },
  runtime: { label: 'runtime', color: 'violet' },
  thunk: { label: 'thunk', color: 'slate' },
  import: { label: 'import', color: 'violet' },
}

/** Origins hidden by "Hide recognised library code". */
export const RECOGNISED = new Set(['library', 'runtime', 'thunk', 'import'])

// Compiler and runtime support: startup, security cookies, stack probes, the
// C runtime of MSVC, MinGW and glibc, and the Go runtime.
const RUNTIME_NAME =
  /^(?:entry\d*|entry\.(?:init|fini)\d*|_?start|_init|_fini|__libc_csu_\w+|_?_?libc_start_main\w*|frame_dummy|register_tm_clones|deregister_tm_clones|__do_global_\w+|_GLOBAL__\w+|__x86\.get_pc_thunk\.\w+|_?_scrt_\w+|__security_\w+|_?_?initterm\w*|__GSHandlerCheck\w*|__report_gsfailure|_?_?_?chkstk\w*|__mingw_\w+|_?_?[tw]?mainCRTStartup|_?_?[tw]?WinMainCRTStartup|_?DllMainCRTStartup\w*|__acrt_\w+|__vcrt_\w+|_RTC_\w+|__C_specific_handler|_?guard_\w+|runtime\.\w+|go\.\w+|type\.\.\w+)$/

const STD_CRATES = new Set(['std', 'core', 'alloc', 'proc_macro'])

/** The name without rizin's flag-space prefixes (`sym.`, `dbg.`, `pdb.<module>.`). */
function bareName(name = '') {
  return name.replace(/^(?:sym\.|dbg\.|pdb\.[^.]+\.)/, '')
}

/**
 * Where a function comes from.
 * @param {object} fn         a worker function (`name`, `kind`, optional `crates`)
 * @param {Set<string>} [inventory] crates seen in the sample (summary `crates`), for demangled names
 * @returns {{ origin: keyof ORIGINS, library: string|null, why: string|null }}
 */
export function classifyFunction(fn, inventory = new Set()) {
  if (fn.kind === 'import') return { origin: 'import', library: null, why: 'imported' }
  const name = fn.name ?? ''
  if (name.startsWith('flirt.')) {
    return { origin: 'library', library: 'FLIRT', why: 'matches a FLIRT library signature' }
  }
  const crates = Object.entries(fn.crates ?? {})
  if (crates.length > 0) {
    const [crate] = crates.sort((a, b) => b[1] - a[1])[0]
    return { origin: 'library', library: crate, why: `panic locations in ${crate}'s sources` }
  }
  const bare = bareName(name)
  if (bare.includes('::')) {
    const root = bare.replace(/^[<&*\s]+/, '').split('::')[0]
    if (STD_CRATES.has(root) || inventory.has(root) || inventory.has(root.replaceAll('_', '-'))) {
      return { origin: 'library', library: STD_CRATES.has(root) ? 'std' : root, why: `symbol in ${root}` }
    }
  }
  if (RUNTIME_NAME.test(bare)) return { origin: 'runtime', library: null, why: 'compiler or runtime support' }
  if (/^(?:sub|case)\./.test(name)) {
    return {
      origin: 'thunk',
      library: null,
      why: name.startsWith('case.') ? 'switch-case fragment' : 'jump to an import',
    }
  }
  return { origin: 'unknown', library: null, why: null }
}

/**
 * The analysis strings as sorted byte ranges, for looking up the string a
 * file offset lands in. UTF-16 strings take two bytes per character.
 */
export function stringRanges(strings = []) {
  return strings
    .map((s) => ({
      start: s.offset,
      end: s.offset + s.value.length * (s.encoding === 'utf-16' ? 2 : 1),
      value: s.value,
      encoding: s.encoding,
    }))
    .sort((a, b) => a.start - b.start)
}

function rangeAt(ranges, offset) {
  let lo = 0
  let hi = ranges.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (ranges[mid].start <= offset) lo = mid + 1
    else hi = mid - 1
  }
  const range = ranges[hi]
  return range && offset < range.end ? range : null
}

/**
 * Link functions to the strings and indicators they reference.
 * A function references a string at file offset `p` (a `&str` may start
 * inside a longer string rizin merged); an indicator at offset `o` is used by
 * the function when `o` falls in the same string, at or after `p`.
 * @param {Array<object>} functions worker functions (`addr`, optional `strings`: file offsets)
 * @param {Array<object>} strings   analysis strings `{ offset, encoding, value }`
 * @param {Array<object>} iocs      analysis indicators `{ kind, value, offset }`
 * @returns {{ byFunction: Map<number, Array<{offset, text, iocs}>>, byIoc: Map<string, number[]> }}
 */
export function linkStrings(functions = [], strings = [], iocs = []) {
  const ranges = stringRanges(strings)
  const refsByString = new Map() // string start (or the offset itself) → [{ addr, offset }]
  const byFunction = new Map()
  for (const fn of functions) {
    if (!fn.strings?.length) continue
    const used = []
    for (const offset of fn.strings) {
      const range = rangeAt(ranges, offset)
      const key = range ? range.start : offset
      if (!refsByString.has(key)) refsByString.set(key, [])
      refsByString.get(key).push({ addr: fn.addr, offset })
      const skip = range ? (offset - range.start) / (range.encoding === 'utf-16' ? 2 : 1) : 0
      used.push({ offset, text: range ? range.value.slice(skip) : null, iocs: [] })
    }
    byFunction.set(fn.addr, used)
  }

  const byIoc = new Map()
  for (const ioc of iocs) {
    const range = rangeAt(ranges, ioc.offset)
    const key = range ? range.start : ioc.offset
    const addrs = [...new Set((refsByString.get(key) ?? []).filter((r) => r.offset <= ioc.offset).map((r) => r.addr))]
    if (addrs.length === 0) continue
    byIoc.set(iocKey(ioc), addrs)
    for (const addr of addrs) {
      for (const use of byFunction.get(addr) ?? []) {
        const useRange = rangeAt(ranges, use.offset)
        if ((useRange ? useRange.start : use.offset) === key && use.offset <= ioc.offset) use.iocs.push(ioc)
      }
    }
  }
  return { byFunction, byIoc }
}

/** Stable key of an indicator (kind, value and position). */
export function iocKey(ioc) {
  return `${ioc.kind}:${ioc.offset}:${ioc.value}`
}

/**
 * The function of the disassembly that contains `addr`: the one starting at
 * it, else the closest one before it whose extent (`size`) covers it.
 * @param {Array<{addr, size}>} sorted functions sorted by address
 * @returns {object|null}
 */
export function functionAt(sorted, addr) {
  let lo = 0
  let hi = sorted.length - 1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (sorted[mid].addr <= addr) lo = mid + 1
    else hi = mid - 1
  }
  const fn = sorted[hi]
  return fn && (fn.addr === addr || addr < fn.addr + (fn.size ?? 0)) ? fn : null
}

/**
 * capa's capabilities per function of the disassembly. capa and rizin split
 * a binary into functions differently, so each address capa reports is
 * credited to the rizin function containing it; the rest stay unplaced.
 * @param {Array<object>} functions worker functions (`addr`, `size`, `kind`)
 * @param {Array<object>} capabilities capa capabilities (`name`, `addresses`)
 * @returns {{ byFunction: Map<number, string[]>, placed: Map<string, number[]> }}
 *   function address → capability names; capability name → function addresses
 */
export function placeCapabilities(functions = [], capabilities = []) {
  const sorted = functions.filter((fn) => fn.kind !== 'import').sort((a, b) => a.addr - b.addr)
  const byFunction = new Map()
  const placed = new Map()
  for (const capability of capabilities) {
    const addrs = new Set()
    for (const address of capability.addresses ?? []) {
      const fn = functionAt(sorted, address)
      if (fn) addrs.add(fn.addr)
    }
    placed.set(capability.name, [...addrs])
    for (const addr of addrs) {
      if (!byFunction.has(addr)) byFunction.set(addr, [])
      byFunction.get(addr).push(capability.name)
    }
  }
  return { byFunction, placed }
}

/**
 * The unrecognised functions most worth reading first, with the reasons:
 * direct calls to suspicious APIs, indicators of compromise used, capa
 * capabilities, suspicious APIs reached through callees, complexity.
 * @param {Array<object>} functions analyzeFunctions() output with `origin` (and `capabilities`)
 * @param {{ byFunction: Map }} links linkStrings() output
 * @returns {Array<{ fn, score, reasons: string[] }>}
 */
export function startHere(functions = [], links = { byFunction: new Map() }, limit = 8) {
  const ranked = []
  for (const fn of functions) {
    if (fn.kind === 'import' || (fn.origin && fn.origin !== 'unknown')) continue
    let score = 0
    const reasons = []
    if (fn.direct === 'high') {
      score += 6
      reasons.push(`calls ${fn.rules.join(', ') || 'suspicious'} APIs`)
    } else if (fn.direct === 'medium') {
      score += 3
      reasons.push(`calls ${fn.rules.join(', ') || 'notable'} APIs`)
    } else if (fn.reaches) {
      score += 1
      reasons.push('reaches a suspicious API through its callees')
    }
    const iocs = (links.byFunction.get(fn.addr) ?? []).flatMap((use) => use.iocs)
    if (iocs.length > 0) {
      score += 3 + Math.min(iocs.length, 3)
      const shown = [...new Set(iocs.map((ioc) => ioc.value))].slice(0, 2).join(', ')
      reasons.push(`uses ${iocs.length === 1 ? 'an indicator' : `${iocs.length} indicators`}: ${shown}`)
    }
    const capabilities = fn.capabilities ?? []
    if (capabilities.length > 0) {
      score += 2 + Math.min(capabilities.length, 3)
      const shown = capabilities.slice(0, 2).join(', ')
      reasons.push(`capa: ${shown}${capabilities.length > 2 ? ` +${capabilities.length - 2}` : ''}`)
    }
    if (fn.cc >= 10) {
      score += 1
      reasons.push(`complex (cyclomatic ${fn.cc})`)
    }
    if (score > 0) ranked.push({ fn, score, reasons })
  }
  return ranked.sort((a, b) => b.score - a.score || b.fn.cc - a.fn.cc).slice(0, limit)
}

/** Display name of a function: the analyst's name when there is one. */
export function nameOf(fn, annotations = {}) {
  return annotations[fn.addr]?.name || displayName(fn.name)
}
