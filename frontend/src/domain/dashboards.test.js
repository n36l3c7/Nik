import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  aggregateRequest,
  arrange,
  bothQueries,
  bucketLabel,
  bytes,
  categories,
  change,
  compact,
  compactGrid,
  dashboardsFromPath,
  dashboardsPath,
  drillQuery,
  duration,
  durationTicks,
  formatOf,
  formatValue,
  gridHeight,
  keyStep,
  measureText,
  newWidget,
  parseGroup,
  parseMeasure,
  readingOrder,
  rowsRequest,
  seriesOf,
  sharingText,
  ticks,
  wholeTicks,
  widgetQuery,
} from './dashboards.js'

test('the address of the page and of one dashboard', () => {
  assert.equal(dashboardsFromPath('/incident/x'), null)
  assert.deepEqual(dashboardsFromPath('/dashboards'), { id: null })
  assert.deepEqual(dashboardsFromPath('/dashboards/ab%20c/'), { id: 'ab c' })
  assert.equal(dashboardsPath(), '/dashboards')
  assert.equal(dashboardsPath('ab c'), '/dashboards/ab%20c')
})

test('what a widget asks: its query, the filter of the dashboard, the time range', () => {
  const board = { filter: 'severity:>=high', filterEntity: 'incidents' }
  const widget = { type: 'bar', entity: 'incidents', query: 'status:open', groupBy: ['owner'], options: {} }
  assert.equal(bothQueries('a:1', ''), 'a:1')
  assert.equal(widgetQuery(widget, board), '(status:open) (severity:>=high)')
  // The filter is for one entity; a widget can leave it out.
  assert.equal(widgetQuery({ ...widget, entity: 'runs' }, board), 'status:open')
  assert.equal(widgetQuery({ ...widget, options: { ignoreFilter: true } }, board), 'status:open')
  assert.deepEqual(aggregateRequest(widget, board, '7d'), {
    entity: 'incidents',
    query: '(status:open) (severity:>=high)',
    groupBy: ['owner'],
    measure: 'count',
    limit: 10,
    timeField: 'created',
    timeRange: '7d',
  })
  // All time, or a widget that ignores the range: no time field, and nothing to compare with.
  const number = { type: 'number', entity: 'runs', query: '', options: { compare: true, timeField: 'finished' } }
  assert.equal(aggregateRequest(number, {}, 'all').timeRange, undefined)
  assert.deepEqual(aggregateRequest(number, {}, '24h'), {
    entity: 'runs',
    query: '',
    groupBy: [],
    measure: 'count',
    limit: 10,
    timeField: 'finished',
    timeRange: '24h',
    compare: 'previous',
  })
  assert.equal(aggregateRequest({ ...number, options: { ignoreRange: true } }, {}, '24h').timeRange, undefined)
  assert.equal(aggregateRequest({ type: 'trend', entity: 'incidents', groupBy: ['created@day'] }, {}, '30d').limit, 500)
  assert.equal(aggregateRequest({ type: 'text' }, {}, '7d'), null)
  // A table asks for rows.
  const table = { type: 'table', entity: 'tasks', query: 'status:overdue', options: { limit: 5 } }
  assert.equal(aggregateRequest(table, {}, '7d'), null)
  assert.deepEqual(rowsRequest(table, {}, '7d'), {
    entity: 'tasks',
    query: '(status:overdue) (created:>=now-7d)',
    limit: 5,
    offset: 0,
  })
  assert.equal(rowsRequest(table, {}, 'all').query, 'status:overdue')
})

test('groups and measures as text, and a new widget of each type', () => {
  assert.deepEqual(parseGroup('created@week'), { field: 'created', bucket: 'week' })
  assert.deepEqual(parseGroup('severity'), { field: 'severity', bucket: '' })
  assert.deepEqual(parseMeasure('median:duration(created,closed)'), {
    fn: 'median',
    field: '',
    from: 'created',
    to: 'closed',
  })
  assert.deepEqual(parseMeasure(''), { fn: 'count', field: '', from: '', to: '' })
  assert.equal(measureText({ fn: 'avg', field: 'score' }), 'avg:score')
  assert.equal(measureText({ fn: 'max', from: 'asked', to: '' }), 'max:duration(asked,now)')
  assert.equal(measureText({ fn: 'avg', field: '' }), 'count')
  assert.deepEqual(newWidget('trend', 'w1').groupBy, ['created@day'])
  assert.equal(newWidget('stacked_bar', 'w1').groupBy.length, 2)
  assert.equal(newWidget('gauge', 'w1').options.target, 10)
  assert.equal(newWidget('text', 'w1').entity, undefined)
  assert.equal(newWidget('number', 'w1').groupBy.length, 0)
})

test('numbers as people read them', () => {
  assert.equal(compact(1284), '1,284')
  assert.equal(compact(12940), '12.9K')
  assert.equal(compact(4_200_000), '4.2M')
  assert.equal(compact(3.14159), '3.14')
  assert.equal(compact(null), '—')
  assert.equal(duration(45), '45s')
  assert.equal(duration(720), '12m')
  assert.equal(duration(7500), '2h 5m')
  assert.equal(duration(7200), '2h')
  assert.equal(duration(3 * 86400 + 4 * 3600 + 59), '3d 4h')
  assert.equal(bytes(1536), '1.5 KB')
  assert.equal(bytes(5 * 1024 ** 3), '5 GB')
  assert.equal(formatOf({ measure: 'avg:duration(created,closed)' }), 'duration')
  assert.equal(formatOf({ measure: 'avg:timeToAssign' }), 'duration')
  assert.equal(formatOf({ measure: 'avg:score' }), 'number')
  assert.equal(formatOf({ measure: 'avg:size', options: { format: 'bytes' } }), 'bytes')
  assert.equal(formatValue(7500, 'duration'), '2h 5m')
  assert.deepEqual(change(14, 9), { text: '+5 (+56%)', direction: 'up' })
  assert.deepEqual(change(3, 4), { text: '−1 (−25%)', direction: 'down' })
  assert.deepEqual(change(3, 0), { text: '+3', direction: 'up' })
  assert.deepEqual(change(2, 2), { text: 'no change', direction: 'same' })
  assert.equal(change(2, null), null)
  assert.equal(bucketLabel('2026-11-17', 'day'), '17 Nov')
  assert.equal(bucketLabel('2026-11', 'month'), 'Nov 2026')
  assert.equal(bucketLabel('2026-11-17T08', 'hour'), '17 Nov 08:00')
  assert.equal(bucketLabel('2026', 'year'), '2026')
  assert.deepEqual(ticks(14), [0, 5, 10, 15])
  assert.deepEqual(ticks(0), [0, 0.25, 0.5, 0.75, 1])
  assert.deepEqual(ticks(3), [0, 1, 2, 3])
  // What is counted has no halves.
  assert.deepEqual(wholeTicks(1), [0, 1])
  assert.deepEqual(wholeTicks(0), [0, 1])
  assert.deepEqual(wholeTicks(3), [0, 1, 2, 3])
  assert.deepEqual(wholeTicks(14), [0, 5, 10, 15])
  assert.deepEqual(durationTicks(4 * 3600), [0, 3600, 7200, 10800, 14400])
})

test('an answer as what a chart draws', () => {
  const one = { columns: [{ name: 'severity', kind: 'ordered' }, { name: 'count' }], rows: [['high', 2], ['', 1]] } // prettier-ignore
  assert.deepEqual(categories(one), [
    { key: 'high', label: 'high', value: 2 },
    { key: '', label: '(none)', value: 1 },
  ])
  const two = {
    columns: [{ name: 'created', kind: 'date', bucket: 'day' }, { name: 'status', kind: 'keyword' }, { name: 'count' }],
    rows: [
      ['2026-11-18', 'open', 1],
      ['2026-11-17', 'closed', 2],
      ['2026-11-17', 'open', 4],
    ],
  } // prettier-ignore
  const drawn = seriesOf(two)
  assert.deepEqual(drawn.x, [
    { key: '2026-11-17', label: '17 Nov' },
    { key: '2026-11-18', label: '18 Nov' },
  ])
  // The largest series first; a stretch a series has nothing in is null.
  assert.deepEqual(
    drawn.series.map((item) => [item.key, item.values, item.total]),
    [
      ['open', [4, 1], 5],
      ['closed', [2, null], 2],
    ],
  )
  // Past eight series the smallest are one "Other" for a count, and left out for a mean.
  const many = { columns: [{ name: 'a' }, { name: 'b' }, { name: 'count' }], rows: [] }
  for (let index = 0; index < 11; index += 1) many.rows.push(['x', `s${index}`, 20 - index])
  const folded = seriesOf(many)
  assert.equal(folded.series.length, 8)
  assert.deepEqual([folded.series[7].label, folded.series[7].total, folded.dropped], ['Other', 13 + 12 + 11 + 10, 0])
  const mean = seriesOf({ ...many, columns: [{ name: 'a' }, { name: 'b' }, { name: 'avg:score' }] })
  assert.deepEqual([mean.series.length, mean.dropped], [7, 4])
})

test('the objects behind a value: the query of the widget and each group at its value', () => {
  const widget = { entity: 'incidents', query: 'status:open', options: {} }
  const columns = [{ name: 'created', bucket: 'day' }, { name: 'owner' }]
  assert.equal(
    drillQuery(widget, {}, columns, ['2026-11-17', 'm "x"']),
    '((status:open) (created:2026-11-17)) (owner:"m \\"x\\"")',
  )
  assert.equal(drillQuery(widget, {}, [{ name: 'owner' }], ['']), '(status:open) (owner:"")')
  assert.equal(
    drillQuery({ entity: 'runs', query: '' }, {}, [{ name: 'started', bucket: 'hour' }], ['2026-11-17T08']),
    'started:>="2026-11-17T08:00:00" started:<"2026-11-17T09:00:00"',
  )
  assert.equal(
    drillQuery({ entity: 'runs', query: '' }, {}, [{ name: 'started', bucket: 'week' }], ['2026-11-16']),
    'started:>="2026-11-16T00:00:00" started:<"2026-11-23T00:00:00"',
  )
  // "Other" is not a value: the query stays the widget's.
  assert.equal(drillQuery(widget, {}, [{ name: 'owner' }], ['\u0000other']), 'status:open')
})

test('the grid: widgets never overlap and leave no hole above', () => {
  const at = (widgets) => widgets.map((w) => [w.id, w.x, w.y, w.w, w.h])
  const grid = [
    { id: 'a', x: 0, y: 0, w: 6, h: 2 },
    { id: 'b', x: 6, y: 0, w: 6, h: 2 },
    { id: 'c', x: 0, y: 2, w: 12, h: 3 },
  ]
  assert.deepEqual(at(compactGrid(grid)), at(grid))
  // A hole above is closed; a widget past the edge is brought back in.
  assert.deepEqual(at(compactGrid([{ id: 'a', x: 10, y: 7, w: 6, h: 2 }])), [['a', 6, 0, 6, 2]])
  // Dragging b onto a: b takes the place, a goes under it, c under both.
  assert.deepEqual(at(arrange(grid, 'b', { x: 0, y: 0 })), [
    ['a', 0, 2, 6, 2],
    ['b', 0, 0, 6, 2],
    ['c', 0, 4, 12, 3],
  ])
  // Making a taller pushes c down and leaves b where it is.
  assert.deepEqual(at(arrange(grid, 'a', { h: 4 })), [
    ['a', 0, 0, 6, 4],
    ['b', 6, 0, 6, 2],
    ['c', 0, 4, 12, 3],
  ])
  assert.equal(gridHeight(arrange(grid, 'a', { h: 4 })), 7)
  assert.deepEqual(
    readingOrder([grid[2], grid[1], grid[0]]).map((w) => w.id),
    ['a', 'b', 'c'],
  )
  assert.deepEqual(keyStep('ArrowLeft', false), { dx: -1, dy: 0 })
  assert.deepEqual(keyStep('ArrowDown', true), { dw: 0, dh: 1 })
  assert.equal(keyStep('Enter', false), null)
})

test('who sees a dashboard, in a few words', () => {
  assert.equal(sharingText({ builtin: true }), 'Shipped with Nik')
  assert.equal(sharingText({ sharedWith: { everyone: true } }), 'Shared with everyone')
  assert.equal(sharingText({ sharedWith: { roles: ['analyst'], users: ['mario'] } }), 'Shared with role analyst, mario')
  assert.equal(sharingText({ sharedWith: {} }), 'Only you')
})
