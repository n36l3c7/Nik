import { useEffect, useMemo, useRef, useState } from 'react'
import {
  aggregateRequest,
  asks,
  bytes,
  categories,
  change as changeOf,
  drillQuery,
  durationTicks,
  formatOf,
  formatValue,
  keyLabel,
  rangeLabel,
  rowsRequest,
  seriesOf,
  ticks,
  wholeTicks,
  widgetQuery,
} from '../../domain/dashboards.js'
import { stateBadge, lastText } from '../../domain/fetch.js'
import { instancePath } from '../../domain/settingsNav.js'
import { setPath } from '../../lib/location.js'
import { ask } from '../../services/widgetData.js'
import { Badge } from '../ui/index.js'
import Markdown from '../tasks/Markdown.jsx'
import Bars from '../charts/Bars.jsx'
import Donut from '../charts/Donut.jsx'
import Plot from '../charts/Plot.jsx'
import { Meter, Stat } from '../charts/Figure.jsx'
import { TableView } from '../charts/shared.jsx'

/*
 * ============================================================================
 * WIDGET — what one widget of a dashboard shows
 * ============================================================================
 *
 * A widget asks the server for its own numbers (as the person looking: the
 * answer never holds what they may not read) and draws them in the form its
 * type names. Every chart can be read as a table instead (`asTable`), and a
 * value can be opened: `onDrill({ entity, query, title })` gives the query of
 * the objects behind it.
 */

/**
 * What a widget asks, and its answer: `{ data, error, loading }`. Asked again when `tick` changes (the
 * dashboard refreshes): the last answer stays while the new one comes, and stays when it fails.
 * `onSettled(id, ok, tick)` tells the page each time the question is answered (or has none).
 */
function useAnswer(widget, board, range, tick, onSettled) {
  const settledRef = useRef(onSettled)
  useEffect(() => {
    settledRef.current = onSettled
  }, [onSettled])
  const request = useMemo(() => {
    if (widget.type === 'storage') return { method: 'GET', path: '/storage' }
    if (widget.type === 'fetch') return { method: 'GET', path: '/fetch' }
    if (widget.type === 'table') return { method: 'POST', path: '/query', body: rowsRequest(widget, board, range) }
    const body = aggregateRequest(widget, board, range)
    return body ? { method: 'POST', path: '/query/aggregate', body } : null
  }, [widget, board, range])
  const key = request ? JSON.stringify(request) : ''
  const [state, setState] = useState({ key: '', data: null, error: null })
  const [seen, setSeen] = useState(tick)

  useEffect(() => {
    if (!request) {
      settledRef.current?.(widget.id, true, tick)
      return undefined
    }
    let cancelled = false
    const fresh = tick !== seen
    ask(request.method, request.path, request.body, { fresh }).then(
      (data) => {
        if (cancelled) return
        setState({ key, data, error: null })
        settledRef.current?.(widget.id, true, tick)
      },
      (failure) => {
        if (cancelled) return
        const forbidden = failure.status === 403
        // The same question asked again keeps its last answer; a different one has none to keep.
        setState((old) => ({
          key,
          data: !forbidden && old.key === key ? old.data : null,
          error: { message: failure.message, forbidden },
        }))
        settledRef.current?.(widget.id, false, tick)
      },
    )
    setSeen(tick)
    return () => {
      cancelled = true
    }
    // The request is its key: a new object with the same content asks nothing.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the request is its key; `seen` only says whether to ask afresh
  }, [key, tick])

  // While a new answer is on its way the last one stays, dimmed: no jump, no flash.
  return {
    data: state.data,
    error: state.key === key ? state.error : null,
    loading: Boolean(request) && state.key !== key,
  }
}

function Message({ children }) {
  return <p className="flex h-full items-center justify-center p-3 text-center text-xs text-fg-muted">{children}</p>
}

function Storage({ data }) {
  const disk = data.disk ?? {}
  const share = disk.total ? Math.round((disk.used / disk.total) * 100) : 0
  return (
    <div className="flex h-full min-h-0 flex-col gap-2">
      <div>
        <p className="text-xs text-fg-muted">
          <span className="text-2xl font-semibold text-fg">{share}%</span> of {bytes(disk.total)} used ·{' '}
          {bytes(disk.free)} free
        </p>
        <div
          role="meter"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={share}
          aria-label="Disk used"
          className="mt-1.5 h-2 overflow-hidden rounded-full bg-line-soft"
        >
          <div
            className={`h-full rounded-full ${share >= 90 ? 'bg-high-line' : 'bg-accent'}`}
            style={{ width: `${share}%` }}
          />
        </div>
      </div>
      <div className="min-h-0 flex-1">
        <Bars
          rows={(data.groups ?? [])
            .filter((group) => group.bytes > 0)
            .sort((a, b) => b.bytes - a.bytes)
            .map((group) => ({ key: group.id, label: group.label ?? group.id, value: group.bytes }))}
          format={bytes}
        />
      </div>
    </div>
  )
}

function FetchHealth({ data }) {
  const connections = data.instances ?? []
  if (!connections.length) return <Message>No instance can fetch.</Message>
  return (
    <ul className="h-full space-y-1.5 overflow-y-auto text-xs">
      {connections.map((connection) => {
        const badge = stateBadge(connection)
        // Its name leads to the instance, where its fetching is seen and set.
        return (
          <li key={connection.instanceId} className="flex items-center gap-2">
            <Badge color={badge.color}>{badge.label}</Badge>
            <button
              type="button"
              title={`${connection.connection}: how it fetches`}
              onClick={() => setPath(instancePath(connection.instanceId, 'fetch'))}
              className="min-w-0 flex-1 truncate text-left text-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {connection.connection}
            </button>
            <span className="truncate text-fg-muted">{lastText(connection) || connection.connector}</span>
          </li>
        )
      })}
    </ul>
  )
}

/** The rows of a table widget: the columns chosen, the first one opening the object when it is an incident. */
function Rows({ widget, data, onOpenIncident }) {
  const columns = widget.options?.columns?.length ? widget.options.columns : ['name']
  const read = (item, name) => {
    const value =
      item[name] ??
      item[`${name}At`] ??
      item[`${name}Id`] ??
      (name === 'owner' ? item.assignee : null) ??
      // A field of the registry that is not a column of the list: what the incident holds for it.
      item.fields?.[name.replace(/^field\./, '')] ??
      null
    if (Array.isArray(value))
      return value.map((part) => (typeof part === 'object' ? JSON.stringify(part) : part)).join(', ')
    if (value && typeof value === 'object') return typeof value.value === 'string' ? value.value : JSON.stringify(value)
    if (typeof value === 'boolean') return value ? 'yes' : 'no'
    if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(value)) return value.slice(0, 16).replace('T', ' ')
    return value == null || value === '' ? '—' : String(value)
  }
  const opens = widget.entity === 'incidents' && onOpenIncident
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-panel">
            <tr className="border-b border-line text-fg-muted">
              {columns.map((name) => (
                <th key={name} className="px-2 py-1 font-medium">
                  {name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {(data.items ?? []).map((item, index) => (
              <tr key={item.id ?? index} className="border-b border-line-soft last:border-0">
                {columns.map((name, at) => (
                  <td key={name} className="max-w-[18rem] truncate px-2 py-1 text-fg">
                    {at === 0 && opens ? (
                      <button
                        type="button"
                        onClick={() => onOpenIncident(item.id)}
                        className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        {read(item, name)}
                      </button>
                    ) : (
                      read(item, name)
                    )}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {(data.items ?? []).length === 0 && <Message>Nothing to show</Message>}
      </div>
      {data.total > (data.items ?? []).length && (
        <p className="shrink-0 pt-1 text-xs text-fg-muted">
          The first {(data.items ?? []).length} of {data.total.toLocaleString('en-US')}
        </p>
      )}
    </div>
  )
}

/**
 * @param {{
 *   widget: object,
 *   board: { filter?: string, filterEntity?: string },
 *   range: string,                       // the time range of the dashboard: '7d', 'all'…
 *   tick?: number,                       // changes when the dashboard refreshes
 *   onSettled?: ((id: string, ok: boolean, tick: number) => void) | null,  // an answer came, or failed
 *   asTable?: boolean,                   // the figures as a table instead of a picture
 *   onDrill?: ((what: { entity: string, query: string, title: string }) => void) | null,
 *   onOpenIncident?: ((id: string) => void) | null,
 * }} props
 */
export default function Widget({
  widget,
  board,
  range,
  tick = 0,
  onSettled = null,
  asTable = false,
  onDrill = null,
  onOpenIncident = null,
}) {
  const { data, error, loading } = useAnswer(widget, board, range, tick, onSettled)
  const format = useMemo(() => {
    const kind = formatOf(widget)
    return (value) => formatValue(value, kind)
  }, [widget])
  const counted = !widget.measure || widget.measure === 'count'
  const ticksOf = formatOf(widget) === 'duration' ? durationTicks : counted ? wholeTicks : ticks

  if (widget.type === 'text') {
    return widget.options?.text ? (
      <div className="h-full overflow-y-auto text-sm">
        <Markdown text={widget.options.text} />
      </div>
    ) : (
      <Message>An empty note</Message>
    )
  }
  if (error && !data) {
    return (
      <Message>
        {error.forbidden ? 'Your roles do not let you see this.' : `This could not be read: ${error.message}`}
      </Message>
    )
  }
  if (!data) return <Message>Loading…</Message>

  const title = widget.title || widget.type
  const drill = (columns, keys, label) =>
    onDrill?.({
      entity: widget.entity,
      query: drillQuery(widget, board, columns, keys),
      title: label ? `${title}: ${label}` : title,
    })
  const columns = data.columns ?? []
  let body

  if (widget.type === 'storage') body = <Storage data={data} />
  else if (widget.type === 'fetch') body = <FetchHealth data={data} />
  else if (widget.type === 'table') body = <Rows widget={widget} data={data} onOpenIncident={onOpenIncident} />
  else if (columns.length === 1) {
    // No group: one figure.
    const total = data.total
    const open =
      onDrill && total ? () => onDrill({ entity: widget.entity, query: widgetQuery(widget, board), title }) : null
    if (widget.type === 'gauge') {
      body = (
        <Meter
          value={total}
          target={widget.options.target}
          text={format(total)}
          targetText={format(widget.options.target)}
          lowerIsBetter={Boolean(widget.options.lowerIsBetter)}
        />
      )
    } else {
      body = (
        <Stat
          value={format(total)}
          change={data.previous ? changeOf(total, data.previous.total, formatOf(widget)) : null}
          against={data.previous ? `the ${rangeLabel(range).replace(/^Last /, '')} before` : null}
          onPick={formatOf(widget) === 'number' ? open : null}
          label={title}
        />
      )
    }
  } else if (columns.length === 2) {
    const rows = categories(data)
    const pick = onDrill ? (key) => drill(columns, [key], keyLabel(key, columns[0])) : null
    if (asTable) {
      body = (
        <TableView
          columns={[columns[0].name, columns[1].name]}
          rows={rows.map((row) => ({ key: row.key, keys: [row.key], cells: [row.label, format(row.value)] }))}
          onPick={onDrill ? (keys) => drill(columns, keys, keyLabel(keys[0], columns[0])) : null}
        />
      )
    } else if (widget.type === 'pie') body = <Donut rows={rows} format={format} onPick={pick} more={data.more} />
    else if (widget.type === 'trend' || columns[0].bucket) {
      body = (
        <Plot
          kind={widget.type === 'trend' ? 'line' : 'columns'}
          x={rows.map((row) => ({ key: row.key, label: row.label }))}
          series={[{ key: columns[1].name, label: title, values: rows.map((row) => row.value) }]}
          ticksOf={ticksOf}
          format={format}
          onPick={pick}
          label={title}
        />
      )
    } else body = <Bars rows={rows} format={format} onPick={pick} ranked={widget.type === 'top'} />
  } else {
    const drawn = seriesOf(data)
    const pick = onDrill ? (key) => drill(columns, [key], keyLabel(key, columns[0])) : null
    if (asTable) {
      body = (
        <TableView
          columns={[columns[0].name, columns[1].name, columns[2].name]}
          rows={(data.rows ?? []).map(([first, second, value]) => ({
            key: `${first}|${second}`,
            keys: [first, second],
            cells: [keyLabel(first, columns[0]), keyLabel(second, columns[1]), format(value)],
          }))}
          onPick={
            onDrill
              ? (keys) => drill(columns, keys, `${keyLabel(keys[0], columns[0])}, ${keyLabel(keys[1], columns[1])}`)
              : null
          }
        />
      )
    } else if (columns[0].bucket) {
      body = (
        <Plot
          kind={widget.type === 'trend' ? 'line' : 'columns'}
          x={drawn.x}
          series={drawn.series}
          ticksOf={ticksOf}
          format={format}
          onPick={pick}
          label={title}
        />
      )
    } else {
      body = (
        <Bars
          rows={drawn.x.map((point, index) => ({
            key: point.key,
            label: point.label,
            values: drawn.series.map((item) => item.values[index]),
          }))}
          series={drawn.series}
          format={format}
          onPick={
            onDrill ? (rowKey, seriesKey) => drill(columns, [rowKey, seriesKey], keyLabel(rowKey, columns[0])) : null
          }
        />
      )
    }
  }

  return (
    <div
      className={`flex h-full min-h-0 flex-col transition-opacity ${loading ? 'opacity-50' : ''}`}
      aria-busy={loading}
    >
      <div className="min-h-0 flex-1">{body}</div>
      {error && (
        <p className="shrink-0 pt-1 text-xs text-med" role="status">
          Could not refresh: {error.message}
        </p>
      )}
      {asks(widget) && data.truncated && (
        <p className="shrink-0 pt-1 text-xs text-med">Worked out from the first 100,000 rows that match.</p>
      )}
    </div>
  )
}
