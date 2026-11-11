import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, Flag, Filter, MessagesSquare, X } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { isShortcutProbe } from '../../../context/ContextMenuContext.jsx'
import FollowStream from './FollowStream.jsx'
import { api } from '../../../services/api.js'
import { formatOffset, hexRows } from '../../../domain/mail.js'
import {
  TIME_FORMATS,
  fieldValue,
  findField,
  followTarget,
  fromBase64,
  hexColor,
  highlight,
  normalizeTree,
} from '../../../domain/network.js'

/*
 * Wireshark's main window for one capture, drawn from sharkd's answers:
 *   - the display filter bar (Wireshark syntax, checked as you type);
 *   - the packet list with Wireshark's colouring rules, loaded by pages;
 *   - the protocol tree of the selected packet (click a field to see its
 *     bytes, "Apply as filter" from its filter expression);
 *   - the bytes in hex and ASCII, the selected field highlighted.
 * Follow Stream opens the conversation of the selected packet. A packet can
 * be flagged into the incident timeline.
 */

const PAGE = 500
const COLUMNS = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
const WIDTHS = ['w-14', 'w-40', 'w-36', 'w-36', 'w-20', 'w-16', '']

/** A call to Wireshark's engine on the capture; resolves to sharkd's result. */
function rpc(captureId, method, params) {
  return api.post(`/captures/${captureId}/rpc`, { method, params }).then((answer) => answer.result)
}

function FilterBar({ captureId, applied, onApply }) {
  const [text, setText] = useState(applied)
  const [state, setState] = useState('idle') // idle | ok | bad
  const [message, setMessage] = useState('')

  useEffect(() => setText(applied), [applied])
  useEffect(() => {
    if (!text.trim()) {
      setState('idle')
      return undefined
    }
    const timer = setTimeout(() => {
      rpc(captureId, 'check', { filter: text })
        .then(() => (setState('ok'), setMessage('')))
        .catch((err) => (setState('bad'), setMessage(err.message)))
    }, 300)
    return () => clearTimeout(timer)
  }, [text, captureId])

  const tone = state === 'ok' ? 'bg-accent-soft/60' : state === 'bad' ? 'bg-high-soft' : 'bg-canvas'
  return (
    <form
      className="flex items-center gap-1.5"
      onSubmit={(event) => {
        event.preventDefault()
        if (state !== 'bad') onApply(text.trim())
      }}
    >
      <Filter className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />
      <input
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder='Apply a display filter… (e.g. http.request.method == "POST")'
        aria-label="Display filter"
        aria-invalid={state === 'bad'}
        title={message}
        spellCheck={false}
        className={`min-w-0 flex-1 border border-line px-2 py-1 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${tone}`}
      />
      <Button type="submit" size="xs" disabled={state === 'bad'}>
        Apply
      </Button>
      {applied && (
        <Button
          type="button"
          variant="ghost"
          size="xs"
          icon={X}
          aria-label="Clear the filter"
          onClick={() => onApply('')}
        />
      )}
    </form>
  )
}

function TreeNode({ node, depth, open, toggle, selected, onSelect, onFilter }) {
  const expanded = open.has(node.path)
  const hasChildren = node.children.length > 0
  return (
    <li>
      <div
        role="treeitem"
        aria-expanded={hasChildren ? expanded : undefined}
        aria-selected={selected === node.path}
        tabIndex={-1}
        onClick={() => onSelect(node)}
        onDoubleClick={() => hasChildren && toggle(node.path)}
        onContextMenu={(event) => {
          // F and C look for a menu here; this is not one.
          if (!node.filter || isShortcutProbe(event)) return
          event.preventDefault()
          onFilter(node.filter)
        }}
        title={node.filter ? `${node.filter} (right-click: apply as filter)` : undefined}
        className={[
          'flex cursor-default items-start gap-1 whitespace-pre-wrap break-all px-1 py-px',
          selected === node.path ? 'bg-accent-soft text-fg' : 'hover:bg-raised',
          node.severity === 'Warning' || node.severity === 'Error' ? 'text-med' : '',
        ].join(' ')}
        style={{ paddingLeft: `${depth * 14 + 4}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation()
              toggle(node.path)
            }}
            aria-label={expanded ? 'Collapse' : 'Expand'}
            className="mt-px shrink-0 text-fg-muted"
          >
            {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          </button>
        ) : (
          <span className="w-3 shrink-0" />
        )}
        <span>{node.label}</span>
      </div>
      {hasChildren && expanded && (
        <ul role="group">
          {node.children.map((child) => (
            <TreeNode
              key={child.path}
              node={child}
              depth={depth + 1}
              open={open}
              toggle={toggle}
              selected={selected}
              onSelect={onSelect}
              onFilter={onFilter}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

function HexPane({ bytes, range }) {
  const rows = useMemo(() => hexRows(bytes), [bytes])
  const inRange = (offset) => range && offset >= range.start && offset < range.end
  return (
    <pre className="h-full overflow-auto p-2 font-mono text-[11px] leading-4 text-fg" aria-label="Packet bytes">
      {rows.map((row) => (
        <div key={row.offset} className="whitespace-pre">
          <span className="text-fg-subtle">{formatOffset(row.offset).slice(4)}</span>
          {'  '}
          {row.hex.map((h, i) => (
            <span key={i} className={inRange(row.offset + i) ? 'bg-accent text-canvas' : ''}>
              {h}
              {i < row.hex.length - 1 ? ' ' : ''}
            </span>
          ))}
          {' '.repeat(Math.max(0, 47 - (row.hex.length * 3 - 1)))}
          {'  '}
          {[...row.ascii].map((c, i) => (
            <span key={i} className={inRange(row.offset + i) ? 'bg-accent text-canvas' : 'text-accent-fg'}>
              {c}
            </span>
          ))}
        </div>
      ))}
    </pre>
  )
}

/**
 * @param {{ capture: object, flags: object, onFlag: (packet: object, timeMs: number | null) => void }} props
 */
export default function PacketView({ capture, flags, onFlag }) {
  const [filter, setFilter] = useState('')
  const [time, setTime] = useState('relative')
  const [rows, setRows] = useState([])
  const [complete, setComplete] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selected, setSelected] = useState(null)
  const [frame, setFrame] = useState(null)
  const [open, setOpen] = useState(new Set())
  const [field, setField] = useState(null)
  const [follow, setFollow] = useState(null)
  const generation = useRef(0)

  const load = useCallback(
    (skip, reset) => {
      const current = ++generation.current
      setLoading(true)
      rpc(capture.id, 'frames', { filter, skip, limit: PAGE, time })
        .then((page) => {
          if (current !== generation.current) return
          setRows((prev) => (reset ? page : [...prev, ...page]))
          setComplete(page.length < PAGE)
          setError(null)
        })
        .catch((err) => current === generation.current && setError(err.message))
        .finally(() => current === generation.current && setLoading(false))
    },
    [capture.id, filter, time],
  )

  useEffect(() => {
    setRows([])
    load(0, true)
  }, [load])

  useEffect(() => {
    if (selected === null) return undefined
    let cancelled = false
    rpc(capture.id, 'frame', { frame: selected })
      .then((result) => {
        if (cancelled) return
        const tree = normalizeTree(result.tree)
        setFrame({ tree, bytes: fromBase64(result.bytes), sources: result.ds ?? [] })
        setOpen(new Set(tree.map((n) => n.path).slice(-1)))
        setField(null)
      })
      .catch((err) => !cancelled && setError(err.message))
    return () => {
      cancelled = true
    }
  }, [selected, capture.id])

  const toggle = (path) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(path)) next.delete(path)
      else next.add(path)
      return next
    })
  const target = frame ? followTarget(frame.tree) : null
  const range = highlight(field)
  const selectedRow = rows.find((r) => r.num === selected)
  const epoch = frame ? Number(fieldValue(findField(frame.tree, 'frame.time_epoch'))) : NaN

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-[20rem] flex-1">
          <FilterBar captureId={capture.id} applied={filter} onApply={setFilter} />
        </div>
        <select
          value={time}
          onChange={(e) => setTime(e.target.value)}
          aria-label="Time format"
          className="border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg"
        >
          {TIME_FORMATS.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
        <Button
          size="xs"
          variant="secondary"
          icon={MessagesSquare}
          disabled={!target}
          onClick={() => setFollow(target)}
          title={target ? `Follow ${target.kind} stream (${target.filter})` : 'Select a TCP or UDP packet'}
        >
          Follow {target?.kind ?? ''} stream
        </Button>
        {onFlag && (
          <Button
            size="xs"
            variant="ghost"
            icon={Flag}
            disabled={!selectedRow}
            onClick={() => onFlag(selectedRow, Number.isFinite(epoch) ? Math.round(epoch * 1000) : null)}
            aria-pressed={Boolean(selectedRow && flags[`pcap:${capture.id}:${selectedRow.num}`])}
          >
            {selectedRow && flags[`pcap:${capture.id}:${selectedRow.num}`] ? 'Flagged' : 'Flag packet'}
          </Button>
        )}
      </div>
      {error && (
        <p role="alert" className="font-mono text-xs text-high">
          {error}
        </p>
      )}
      <div className="grid h-[70vh] min-h-0 grid-rows-[minmax(0,5fr)_minmax(0,4fr)] gap-1 font-mono">
        <div className="min-h-0 overflow-auto border border-line bg-panel">
          <table className="w-full table-fixed border-collapse text-[11px]" aria-label="Packets">
            <thead className="sticky top-0 bg-panel text-left text-fg-muted">
              <tr className="border-b border-line">
                {COLUMNS.map((c, i) => (
                  <th key={c} className={`${WIDTHS[i]} px-1.5 py-1 font-normal`}>
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const active = row.num === selected
                return (
                  <tr
                    key={row.num}
                    onClick={() => setSelected(row.num)}
                    aria-selected={active}
                    style={active ? undefined : { backgroundColor: hexColor(row.bg), color: hexColor(row.fg) }}
                    className={active ? 'cursor-default bg-accent text-canvas' : 'cursor-default'}
                    title={row.comments?.join('\n')}
                  >
                    {row.c.map((value, i) => (
                      <td key={i} className="truncate px-1.5 py-px">
                        {i === 0 && flags[`pcap:${capture.id}:${row.num}`] ? '⚑ ' : ''}
                        {value}
                      </td>
                    ))}
                  </tr>
                )
              })}
            </tbody>
          </table>
          <div className="p-2 text-center text-[11px] text-fg-muted">
            {loading ? (
              'Loading…'
            ) : complete ? (
              `${rows.length.toLocaleString('en-US')} packet${rows.length === 1 ? '' : 's'}${filter ? ' match the filter' : ''}`
            ) : (
              <Button size="xs" variant="ghost" onClick={() => load(rows.length, false)}>
                Load {PAGE} more
              </Button>
            )}
          </div>
        </div>
        <div className="grid min-h-0 grid-cols-[minmax(0,3fr)_minmax(0,2fr)] gap-1">
          <ul
            role="tree"
            aria-label="Packet details"
            className="min-h-0 overflow-auto border border-line bg-panel py-1 text-[11px] text-fg"
          >
            {frame ? (
              frame.tree.map((node) => (
                <TreeNode
                  key={node.path}
                  node={node}
                  depth={0}
                  open={open}
                  toggle={toggle}
                  selected={field?.path}
                  onSelect={setField}
                  onFilter={setFilter}
                />
              ))
            ) : (
              <li className="p-2 text-fg-muted">Select a packet.</li>
            )}
          </ul>
          <div className="min-h-0 border border-line bg-panel">
            {frame ? <HexPane bytes={frame.bytes} range={field?.source ? null : range} /> : null}
          </div>
        </div>
      </div>
      <FollowStream captureId={capture.id} target={follow} onClose={() => setFollow(null)} />
    </div>
  )
}
