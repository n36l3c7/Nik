import assert from 'node:assert/strict'
import { test } from 'node:test'
import { chartNote, chartPath, chartSummary, chartValue, chartWidgets, linkedWhy } from './linked.js'

test('a linked incident says why it is there', () => {
  assert.equal(linkedWhy({ related: true, shared: 0, indicators: [] }), 'related')
  assert.equal(
    linkedWhy({ related: false, shared: 1, indicators: [{ type: 'ip', value: '185.220.101.47' }] }),
    'shares 1 indicator: 185.220.101.47',
  )
  assert.equal(
    linkedWhy({
      related: true,
      shared: 5,
      indicators: [
        { type: 'ip', value: '185.220.101.47' },
        { type: 'domain', value: 'inv0ice.example' },
      ],
    }),
    'related · shares 5 indicators: 185.220.101.47, inv0ice.example and 3 more',
  )
  assert.equal(linkedWhy({ shared: 2 }), 'shares 2 indicators')
  assert.equal(linkedWhy(null), '')
})

test('the chart of a widget is asked for the incident, once a chart was chosen', () => {
  assert.equal(chartPath('i1', { dashboard: '', widget: '', field: '' }), null)
  assert.equal(chartPath('i1', { dashboard: 'd1', widget: '', field: 'host' }), null)
  assert.equal(chartPath(null, { dashboard: 'd1', widget: 'w1' }), null)
  assert.equal(
    chartPath('a/b', { dashboard: 'd 1', widget: 'w1', field: 'host' }),
    '/incidents/a%2Fb/chart?dashboard=d+1&widget=w1&field=host',
  )
  assert.equal(chartPath('i1', { dashboard: 'd1', widget: 'w1' }), '/incidents/i1/chart?dashboard=d1&widget=w1&field=')
  assert.equal(chartValue('WS-0231'), 'WS-0231')
  assert.equal(chartValue(['a', 'b']), 'a, b')
  assert.equal(chartValue(null), '')
  assert.equal(
    chartNote({ board: { name: 'SOC overview' }, field: 'host', value: 'WS-0231' }),
    'SOC overview · narrowed to host: WS-0231',
  )
  assert.equal(chartNote(null), '')
})

test('the editor of a type says which chart a widget shows', () => {
  const boards = [
    {
      id: 'd1',
      name: 'SOC overview',
      widgets: [
        { id: 'w1', title: 'By severity', type: 'bar', entity: 'incidents' },
        { id: 'w2', title: '', type: 'trend', entity: 'incidents' },
        { id: 'w3', type: 'text' },
        { id: 'w4', type: 'storage' },
      ],
    },
  ]
  // A text, the disk and the fetch health ask no query: nothing to narrow.
  assert.deepEqual(
    chartWidgets(boards[0]).map((widget) => widget.id),
    ['w1', 'w2'],
  )
  assert.deepEqual(chartWidgets(null), [])
  assert.equal(chartSummary({ dashboard: '', widget: '' }, boards), 'No chart was chosen yet.')
  assert.equal(
    chartSummary({ dashboard: 'd1', widget: 'w1', field: 'host' }, boards),
    'SOC overview / By severity · narrowed by host',
  )
  assert.equal(
    chartSummary({ dashboard: 'd1', widget: 'w2', field: '' }, boards),
    'SOC overview / trend · no field chosen yet',
  )
  assert.equal(
    chartSummary({ dashboard: 'd1', widget: 'gone', field: 'host' }, boards),
    'SOC overview / a widget that is gone · narrowed by host',
  )
  // The dashboards were not read yet, or this one is not shared with who edits the type.
  assert.equal(chartSummary({ dashboard: 'd9', widget: 'w1', field: 'host' }, null), 'A chart · narrowed by host')
})
