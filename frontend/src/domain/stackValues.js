/*
 * What the Stack values panel (components/evidence/StackPanel.jsx) does with the answer of `GET .../stack`:
 * the three orders, the share of each value, and the text it copies. The shape of a value is
 * `{ value, count, first, last }`.
 */

export const ORDERS = [
  { id: 'rare', label: 'Rarest first' },
  { id: 'common', label: 'Most common' },
  { id: 'az', label: 'A → Z' },
]

/** How many values the panel asks for: all the choices of A → Z must be there to be sorted, 100 are enough for the others. */
export const LIMITS = { rare: 100, common: 100, az: 500 }

/** The order the server is asked for: A → Z is the server's most common, sorted here. */
export const serverOrder = (order) => (order === 'az' ? 'common' : order)

const compare = (a, b) => String(a.value).localeCompare(String(b.value), 'en', { numeric: true, sensitivity: 'base' })

/** The values in the order chosen; the server's order is kept for the two it knows. */
export const sortValues = (values = [], order = 'rare') => (order === 'az' ? [...values].sort(compare) : values)

/**
 * The share of each value among the values listed: `{ value, count, first, last, share }`, `share` from 0 to 1,
 * and `bar` from 0 to 1 against the largest count (the length of the bar, which a share of 0.2% would not make visible).
 * `listed` is the sum of the counts, the figure the shares are of.
 */
export function withShares(values = []) {
  const listed = values.reduce((sum, item) => sum + item.count, 0)
  const largest = values.reduce((most, item) => Math.max(most, item.count), 0)
  return {
    listed,
    rows: values.map((item) => ({
      ...item,
      share: listed > 0 ? item.count / listed : 0,
      bar: largest > 0 ? item.count / largest : 0,
    })),
  }
}

/** "0.4%", "12%", "<0.1%": a share as the table writes it. */
export function percentText(share) {
  if (!(share > 0)) return '0%'
  const percent = share * 100
  if (percent < 0.1) return '<0.1%'
  return percent < 10 ? `${percent.toFixed(1)}%` : `${Math.round(percent)}%`
}

/** A cell of a tab-separated text: tabs and line breaks in a value become spaces. */
const cell = (value) => String(value ?? '').replace(/[\t\r\n]+/g, ' ')

/** The values as tab-separated text with a header line, for a spreadsheet: value, count, share, first and last seen (ISO). */
export function tsvOf(rows, label = 'value') {
  const when = (ms) => (Number.isFinite(ms) ? new Date(ms).toISOString() : '')
  const lines = [
    ['value', 'count', 'share', 'first seen', 'last seen'].map((name, i) => (i === 0 ? cell(label) : name)),
  ]
  for (const row of rows) {
    lines.push([cell(row.value), row.count, `${(row.share * 100).toFixed(2)}%`, when(row.first), when(row.last)])
  }
  return lines.map((line) => line.join('\t')).join('\n')
}

/** The line that says what the order puts first. */
export function hint(order) {
  if (order === 'rare') return 'The values seen the fewest times are at the top: the rare one is the one to look at.'
  if (order === 'common') return 'The values seen the most times are at the top.'
  return 'The values in alphabetical order.'
}

/** What was counted, in a line: "2,418 records, 61 values", "100+ values" when the server stopped counting. */
export function countedText(answer, listed) {
  if (!answer) return ''
  const values = `${answer.distinct.toLocaleString('en-US')}${answer.distinctCapped ? '+' : ''} distinct values`
  const records = listed > 0 ? `${listed.toLocaleString('en-US')} records listed, ` : ''
  const missing = answer.missing > 0 ? `, ${answer.missing.toLocaleString('en-US')} records without one` : ''
  return `${records}${values}${missing}`
}
