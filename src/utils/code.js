/*
 * ============================================================================
 * DISASSEMBLY (Code view) — pure helpers over the analyzer worker's output
 * ============================================================================
 *
 * The worker (analyzer/, rizin) returns functions with their calls and, per
 * function, a control-flow graph of basic blocks. These helpers turn that into
 * what the UI draws: readable names, SOC severity of the APIs a function
 * calls (directly or through other functions), the call graph around one
 * function and the CFG of one function as nodes and typed edges for the ELK
 * layout.
 */

/** `0x401a30` from a number (`—` when missing). */
export function hex(value) {
  return typeof value === 'number' ? `0x${value.toString(16)}` : '—'
}

/**
 * Readable function name: rizin's import prefixes are dropped
 * (`sym.imp.KERNEL32.dll_VirtualAllocEx` → `VirtualAllocEx`, `sym.imp.puts` → `puts`).
 */
export function displayName(name = '') {
  const bare = name.replace(/^(sym\.imp\.|imp\.|reloc\.)/, '')
  const dll = bare.match(/^[\w-]+\.(?:dll|DLL|so[.\d]*|dylib)_(.+)$/)
  return dll ? dll[1] : bare
}

const RANK = { high: 2, medium: 1 }
const worst = (a, b) => ((RANK[b] ?? 0) > (RANK[a] ?? 0) ? b : a)

/**
 * Enrich the worker's functions for the UI:
 * `{ ...fn, display, direct, severity, reaches, rules }` where `direct` is the
 * worst SOC severity among the names it calls, `reaches` the worst severity
 * reachable through its callees (the call graph is walked once, cycles safe)
 * and `rules` the matched rule labels.
 * @param {Array<object>} functions  `functions` from GET /samples/{sha}/code
 * @param {object} engine            SOC engine (malware ruleset)
 */
export function analyzeFunctions(functions = [], engine) {
  const byAddr = new Map(functions.map((fn) => [fn.addr, fn]))
  const direct = new Map()
  const rules = new Map()
  for (const fn of functions) {
    let severity = null
    const labels = new Set()
    const names = fn.kind === 'import' ? [fn.name] : fn.calls.map((call) => call.name)
    for (const name of names) {
      const soc = engine.analyze({ kind: 'malware', title: displayName(name) })
      severity = worst(severity, soc.severity)
      for (const rule of soc.keywordMatches) labels.add(rule.label)
    }
    direct.set(fn.addr, severity)
    rules.set(fn.addr, [...labels])
  }

  const reach = new Map()
  const visit = (addr, stack) => {
    if (reach.has(addr)) return reach.get(addr)
    if (stack.has(addr)) return direct.get(addr) ?? null
    stack.add(addr)
    let severity = direct.get(addr) ?? null
    for (const call of byAddr.get(addr)?.calls ?? []) {
      if (call.addr != null && byAddr.has(call.addr)) severity = worst(severity, visit(call.addr, stack))
    }
    stack.delete(addr)
    reach.set(addr, severity)
    return severity
  }

  return functions.map((fn) => ({
    ...fn,
    display: displayName(fn.name),
    direct: direct.get(fn.addr) ?? null,
    reaches: visit(fn.addr, new Set()),
    rules: rules.get(fn.addr) ?? [],
  }))
}

/**
 * The call graph around one function, `depth` calls deep:
 * `{ nodes: [{ id, label, kind, severity, root }], edges: [{ id, from, to, hot }] }`.
 * Imports and unresolved targets become leaf nodes. `hot` marks edges that
 * lead to a suspicious API. Capped at `limit` nodes.
 * @param {Array<object>} functions  analyzeFunctions() output
 * @param {object} engine             SOC engine, for callees outside the function list
 */
export function callGraph(functions, rootAddr, engine, { depth = 2, limit = 80 } = {}) {
  const byAddr = new Map(functions.map((fn) => [fn.addr, fn]))
  const root = byAddr.get(rootAddr)
  if (!root) return { nodes: [], edges: [], truncated: false }
  const nodes = new Map()
  const edges = []
  let truncated = false

  const addNode = (id, data) => {
    if (nodes.has(id)) return true
    if (nodes.size >= limit) {
      truncated = true
      return false
    }
    nodes.set(id, { id, ...data })
    return true
  }
  addNode(String(root.addr), { label: root.display, kind: root.kind, severity: root.reaches, root: true })

  let frontier = [root]
  for (let level = 0; level < depth && frontier.length > 0; level += 1) {
    const next = []
    for (const fn of frontier) {
      for (const call of fn.calls ?? []) {
        const target = call.addr != null ? byAddr.get(call.addr) : null
        const id = target ? String(target.addr) : `ext:${call.name}`
        const isNew = !nodes.has(id)
        const severity = target
          ? target.reaches
          : engine.analyze({ kind: 'malware', title: displayName(call.name) }).severity
        const kind = target ? target.kind : 'import'
        if (!addNode(id, { label: target ? target.display : displayName(call.name), kind, severity, root: false }))
          continue
        const edgeId = `${fn.addr}->${id}`
        if (!edges.some((e) => e.id === edgeId)) {
          edges.push({ id: edgeId, from: String(fn.addr), to: id, hot: Boolean(severity) })
        }
        if (isNew && target && target.kind !== 'import') next.push(target)
      }
    }
    frontier = next
  }
  return { nodes: [...nodes.values()], edges, truncated }
}

/**
 * CFG of one function as nodes and typed edges for the layout:
 * nodes `{ id, addr, lines: [{ text, type }], hot }`, edges
 * `{ id, from, to, kind: 't' | 'f' | 'j', back }`. A block with both a jump and
 * a fail successor is a conditional branch (jump = taken, fail = not taken);
 * a single successor is unconditional. `back` marks edges to a block at a
 * lower or equal address, i.e. loops.
 * @param {{ blocks: Array<object> }} cfg   GET /samples/{sha}/code/functions/{addr}
 * @param {object} engine
 * @param {Map<string, string>} [renames]  rizin name → analyst's name, applied to the operands
 */
export function cfgGraph(cfg, engine, renames = new Map()) {
  const blocks = cfg?.blocks ?? []
  const known = new Set(blocks.map((b) => b.addr))
  const rename = (text) => (renames.size ? text.replace(/[A-Za-z_][\w.$@:]*/g, (t) => renames.get(t) ?? t) : text)
  const nodes = blocks.map((block) => ({
    id: String(block.addr),
    addr: block.addr,
    lines: block.ops.map((op) => ({ text: rename(op.text), type: op.type })),
    hot: block.ops.some(
      (op) =>
        op.type.endsWith('call') &&
        engine.analyze({ kind: 'malware', title: displayName(op.text.replace(/^\S+\s+/, '')) }).severity,
    ),
  }))
  const edges = []
  for (const block of blocks) {
    const conditional = block.jump != null && block.fail != null
    const add = (to, kind) => {
      if (to == null || !known.has(to)) return
      edges.push({
        id: `${block.addr}-${kind}-${to}`,
        from: String(block.addr),
        to: String(to),
        kind,
        back: to <= block.addr,
      })
    }
    add(block.jump, conditional ? 't' : 'j')
    if (conditional) add(block.fail, 'f')
  }
  return { nodes, edges }
}

/**
 * Pseudo-C split into lines of styled segments for rendering:
 * `[[{ text, kind, target }]]`. `spans` come from the worker
 * (`[start, end, kind]` or `[start, end, 'f', address]`, sorted, not
 * overlapping); text between spans has `kind: null`. Line breaks inside a
 * span split it, so every segment sits on one line.
 * @param {string} code
 * @param {Array<Array>} spans
 */
export function decompiledLines(code = '', spans = []) {
  const lines = [[]]
  const push = (text, kind, target) => {
    text.split('\n').forEach((part, i) => {
      if (i > 0) lines.push([])
      if (part) lines[lines.length - 1].push({ text: part, kind, target })
    })
  }
  let at = 0
  for (const [start, end, kind, target = null] of spans) {
    if (start < at || end > code.length) continue
    if (start > at) push(code.slice(at, start), null, null)
    push(code.slice(start, end), kind, target)
    at = end
  }
  if (at < code.length) push(code.slice(at), null, null)
  return lines
}

/** Pixel size of a node from its text lines (monospace 11px). */
export const NODE_METRICS = { charWidth: 6.7, lineHeight: 15, padX: 10, padY: 8, header: 20 }

export function nodeSize(lines, minChars = 14) {
  const { charWidth, lineHeight, padX, padY, header } = NODE_METRICS
  const longest = Math.max(minChars, ...lines.map((line) => line.length))
  return { width: Math.ceil(longest * charWidth + padX * 2), height: header + padY * 2 + lines.length * lineHeight }
}
