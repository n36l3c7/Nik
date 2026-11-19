import { useState } from 'react'
import { ArrowDown, ArrowUp, Eye, EyeOff, GripVertical, Plus, RotateCcw, X } from 'lucide-react'
import { ANALYSIS_TABS } from '../../../config/tabs.js'
import { NOTE_MAX, gridSections } from '../../../domain/layoutGrid.js'
import { QUICK_KINDS, QUICK_MAX } from '../../../domain/quickView.js'
import {
  PAGES_MAX,
  PAGE_NAME_MAX,
  addPage,
  addQuick,
  canAddPage,
  canAddQuick,
  closeFields,
  closeSections,
  closeTag,
  moveCloseSection,
  moveQuick,
  moveTab,
  pageIdOf,
  pageOf,
  placeTab,
  quickFreeSections,
  quickList,
  quickTag,
  removeQuick,
  tabRows,
  tabTag,
  toggleCloseSection,
  toggleTab,
  updateQuick,
} from '../../../domain/typePages.js'
import { Button, Modal } from '../../ui/index.js'
import TypePageEditor from './TypePageEditor.jsx'

/*
 * ============================================================================
 * THE PAGES OF A TYPE — its tabs, the pages it adds, its close form, its quick view (6.2)
 * ============================================================================
 *
 * The two sides stand side by side in a wide window, and one above the other
 * otherwise: a grid of twelve columns is not arranged in half a window.
 *
 *   left    "Tabs of the incident": every tab of the bar in the order of this
 *           type, each with a grip to drag it (and arrows for the keyboard),
 *           an eye to hide or show it, and a tag that says what it is: a tab
 *           of Nik, which is moved or hidden and never redrawn; the Summary,
 *           which is a page and is never hidden; a page of the type's own.
 *           "Add a page…" makes one. Under them, the other views of the type:
 *           the close form and the quick view.
 *   right   what is chosen on the left: the grid of the Summary or of a page
 *           (TypePageEditor), the sections of the close form, or the blocks
 *           of the quick view.
 *
 * Nothing is saved until "Save the type".
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const CAPTION = 'font-mono text-[11px] uppercase tracking-wider text-fg-muted'
const ROW = 'flex items-center gap-1.5 border px-2 py-1 text-sm'
const TAG = 'shrink-0 border border-line px-1.5 font-mono text-[11px] leading-5 text-fg-muted'
const DRAG = 'application/x-nik-tab'
// The tabs of Nik that are on the bar: the kinds of evidence are ordered inside the Evidence tab.
const BAR = ANALYSIS_TABS.filter((tab) => !tab.evidence).map((tab) => ({ id: tab.id, label: tab.label }))

/** The sections the form of closing shows, chosen and ordered. */
function CloseFormEditor({ layout, onLayout, known, flags }) {
  const chosen = closeSections(layout)
  const others = (layout.sections ?? []).filter((section) => !chosen.some((item) => item.id === section.id))
  const summary = (section) => {
    const fields = closeFields(section, known, flags)
    const needed = fields.filter((item) => item.needed).length
    if (fields.length === 0) return 'no field to edit'
    return `${fields.length} ${fields.length === 1 ? 'field' : 'fields'}${needed ? `, ${needed} to close` : ''}`
  }
  return (
    <section aria-label="Close form" className="flex min-w-0 flex-col gap-3 border border-line bg-panel p-3">
      <div>
        <h3 className={CAPTION}>Close form</h3>
        <p className="text-sm text-fg-muted">
          What the Close dialog asks for an incident of this type. It always asks the reason and a note; choose the
          sections it shows with them. Their fields are edited there, and a field marked “to close” must be filled
          before the incident closes.
        </p>
      </div>
      <ul aria-label="Sections of the close form" className="flex flex-col gap-1">
        {chosen.map((section, at) => (
          <li key={section.id} className={`${ROW} border-line-soft bg-canvas`}>
            <span className="min-w-0 flex-1 truncate text-fg">{section.title}</span>
            <span className={TAG}>{summary(section)}</span>
            <Button
              variant="ghost"
              size="xs"
              icon={ArrowUp}
              aria-label={`Move ${section.title} up in the close form`}
              disabled={at === 0}
              onClick={() => onLayout(moveCloseSection(layout, section.id, -1))}
            />
            <Button
              variant="ghost"
              size="xs"
              icon={ArrowDown}
              aria-label={`Move ${section.title} down in the close form`}
              disabled={at === chosen.length - 1}
              onClick={() => onLayout(moveCloseSection(layout, section.id, 1))}
            />
            <Button
              variant="ghost"
              size="xs"
              icon={X}
              aria-label={`Take ${section.title} out of the close form`}
              onClick={() => onLayout(toggleCloseSection(layout, section.id))}
            />
          </li>
        ))}
        {chosen.length === 0 && (
          <li className="border border-dashed border-line px-2 py-3 text-center text-xs text-fg-muted">
            No section yet: the dialog asks the reason, a note, and the fields marked “to close”, as it always did.
          </li>
        )}
      </ul>
      {others.length > 0 && (
        <div className="flex flex-col gap-1">
          <h4 className={CAPTION}>Sections to add</h4>
          <ul aria-label="Sections to add to the close form" className="flex flex-wrap gap-2">
            {others.map((section) => (
              <li key={section.id}>
                <Button
                  variant="secondary"
                  size="xs"
                  icon={Plus}
                  title={summary(section)}
                  onClick={() => onLayout(toggleCloseSection(layout, section.id))}
                >
                  {section.title}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="text-xs text-fg-muted">
        The fields of a section, and which are needed to close, are chosen under “Fields and sections”.
      </p>
    </section>
  )
}

/** The blocks of the quick view, one under the other. */
function QuickViewEditor({ layout, onLayout }) {
  const [adding, setAdding] = useState('')
  const blocks = quickList(layout)
  const sections = gridSections(layout)
  const free = quickFreeSections(layout)
  const offered = QUICK_KINDS.filter((kind) => canAddQuick(layout, kind.id))
  const label = (block) => QUICK_KINDS.find((kind) => kind.id === block.kind)?.label ?? block.kind
  return (
    <section aria-label="Quick view" className="flex min-w-0 flex-col gap-3 border border-line bg-panel p-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <h3 className={CAPTION}>Quick view</h3>
          <p className="text-sm text-fg-muted">
            The panel a click on a row of the incident list opens: one narrow column of blocks, {QUICK_MAX} at most.{' '}
            {blocks.length === 0
              ? 'This type has none of its own: Nik shows the details, the first section, the numbers of the evidence and the last of the War Room.'
              : 'These are the blocks of this type, in order.'}
          </p>
        </div>
        <label className="flex flex-col gap-1 text-xs text-fg-muted" htmlFor="quick-add-kind">
          Add a block
          <span className="flex gap-2">
            <select
              id="quick-add-kind"
              value={adding}
              onChange={(event) => setAdding(event.target.value)}
              className={`${INPUT} w-56 cursor-pointer`}
            >
              <option value="">Choose a kind…</option>
              {offered.map((kind) => (
                <option key={kind.id} value={kind.id}>
                  {kind.label}
                </option>
              ))}
            </select>
            <Button
              variant="secondary"
              size="sm"
              icon={Plus}
              disabled={!adding}
              onClick={() => {
                onLayout(addQuick(layout, adding))
                setAdding('')
              }}
            >
              Add
            </Button>
          </span>
        </label>
        {blocks.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            icon={RotateCcw}
            title="Forget these blocks: Nik makes the quick view again"
            onClick={() => {
              const { quick: _gone, ...rest } = layout
              onLayout(rest)
            }}
          >
            Back to the generated view
          </Button>
        )}
      </div>
      <ol aria-label="Blocks of the quick view" className="flex max-w-md flex-col gap-1">
        {blocks.map((block, at) => (
          <li
            key={`${block.kind}:${block.section ?? at}`}
            className="flex flex-col gap-1.5 border border-line-soft bg-canvas p-2"
          >
            <div className="flex items-center gap-1.5 text-sm">
              <span className="min-w-0 flex-1 truncate text-fg">{label(block)}</span>
              <Button
                variant="ghost"
                size="xs"
                icon={ArrowUp}
                aria-label={`Move block ${at + 1} up`}
                disabled={at === 0}
                onClick={() => onLayout(moveQuick(layout, at, -1))}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={ArrowDown}
                aria-label={`Move block ${at + 1} down`}
                disabled={at === blocks.length - 1}
                onClick={() => onLayout(moveQuick(layout, at, 1))}
              />
              <Button
                variant="ghost"
                size="xs"
                icon={X}
                aria-label={`Remove block ${at + 1}`}
                onClick={() => onLayout(removeQuick(layout, at))}
              />
            </div>
            {block.kind === 'section' && (
              <select
                aria-label={`Section of block ${at + 1}`}
                value={block.section}
                onChange={(event) => onLayout(updateQuick(layout, at, { section: event.target.value }))}
                className={`${INPUT} cursor-pointer`}
              >
                {sections
                  .filter((section) => section.id === block.section || free.some((item) => item.id === section.id))
                  .map((section) => (
                    <option key={section.id} value={section.id}>
                      {section.title}
                    </option>
                  ))}
              </select>
            )}
            {block.kind === 'note' && (
              <textarea
                aria-label={`Text of block ${at + 1}`}
                value={block.text}
                rows={2}
                maxLength={NOTE_MAX}
                placeholder="What to check first, who to call."
                onChange={(event) => onLayout(updateQuick(layout, at, { text: event.target.value }))}
                className={`${INPUT} resize-y`}
              />
            )}
          </li>
        ))}
        {blocks.length === 0 && (
          <li className="border border-dashed border-line px-2 py-3 text-center text-xs text-fg-muted">
            No block of its own: the generated view.
          </li>
        )}
      </ol>
    </section>
  )
}

/**
 * @param {{
 *   type: object,                      // the type as the builder holds it (its fields say what is needed to close)
 *   layout: object,
 *   onLayout: (layout: object) => void,
 *   fields: object[],                  // the registry
 *   known: object,                     // the registry by name
 * }} props
 */
export default function TypePagesEditor({ type, layout, onLayout, fields, known }) {
  // What the right side edits: { view: 'page', page: null | id } | { view: 'close' } | { view: 'quick' }.
  const [chosen, setChosen] = useState({ view: 'page', page: null })
  const [naming, setNaming] = useState(null) // the name of the page being added
  const [said, setSaid] = useState('')
  const rows = tabRows(layout, BAR)
  // A page that was deleted is no longer what is edited.
  const page = chosen.view === 'page' && chosen.page && pageOf(layout, chosen.page) ? chosen.page : null
  const typeFields = fields.filter(
    (field) =>
      field.appliesTo === 'incident' && (layout.sections ?? []).some((section) => section.fields.includes(field.name)),
  )

  const move = (row, by) => {
    onLayout(moveTab(layout, BAR, row.id, by))
    setSaid(`${row.label} moved ${by < 0 ? 'up' : 'down'}.`)
  }
  const create = (event) => {
    event.preventDefault()
    const made = addPage(layout, naming)
    if (!made.id) return
    onLayout(made.layout)
    setChosen({ view: 'page', page: made.id })
    setNaming(null)
  }

  return (
    // The grid of a page needs its twelve columns: the lists stand beside it only where there is room for both.
    <div className="grid items-start gap-4 2xl:grid-cols-[300px_minmax(0,1fr)]">
      <aside className="grid items-start gap-4 md:grid-cols-2 2xl:grid-cols-1">
        <section aria-label="Tabs of the incident" className="flex flex-col gap-2 border border-line bg-panel p-3">
          <div className="flex items-center gap-2">
            <h3 className={`${CAPTION} flex-1`}>Tabs of the incident</h3>
            <Button
              variant="secondary"
              size="xs"
              icon={Plus}
              disabled={!canAddPage(layout)}
              title={canAddPage(layout) ? undefined : `A type has ${PAGES_MAX} pages of its own at most`}
              onClick={() => setNaming('')}
            >
              Add a page…
            </Button>
          </div>
          <ul className="flex flex-col gap-1">
            {rows.map((row, at) => {
              const pageId = pageIdOf(row.id)
              const editable = row.kind !== 'nik'
              const on = chosen.view === 'page' && (row.kind === 'summary' ? page === null : pageId === page)
              return (
                <li
                  key={row.id}
                  draggable
                  onDragStart={(event) => event.dataTransfer.setData(DRAG, row.id)}
                  onDragOver={(event) => event.dataTransfer.types.includes(DRAG) && event.preventDefault()}
                  onDrop={(event) => {
                    const dragged = event.dataTransfer.getData(DRAG)
                    if (!dragged) return
                    event.preventDefault()
                    onLayout(placeTab(layout, BAR, dragged, row.id))
                  }}
                  className={`${ROW} ${editable && on ? 'border-accent-strong bg-raised' : 'border-line-soft bg-canvas'} ${row.hidden ? 'opacity-60' : ''}`}
                >
                  <GripVertical className="h-3.5 w-3.5 shrink-0 cursor-grab text-fg-subtle" aria-hidden="true" />
                  {editable ? (
                    <button
                      type="button"
                      aria-pressed={on}
                      title={`Arrange the page ${row.label}`}
                      onClick={() => setChosen({ view: 'page', page: pageId })}
                      className="min-w-0 flex-1 truncate text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {row.label}
                    </button>
                  ) : (
                    <span className="min-w-0 flex-1 truncate text-fg">{row.label}</span>
                  )}
                  <span className={TAG}>{tabTag(row)}</span>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={ArrowUp}
                    aria-label={`Move ${row.label} up`}
                    disabled={at === 0}
                    onClick={() => move(row, -1)}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={ArrowDown}
                    aria-label={`Move ${row.label} down`}
                    disabled={at === rows.length - 1}
                    onClick={() => move(row, 1)}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={row.hidden ? EyeOff : Eye}
                    aria-label={`${row.hidden ? 'Show' : 'Hide'} ${row.label}`}
                    aria-pressed={row.hidden}
                    disabled={row.kind === 'summary'}
                    title={
                      row.kind === 'summary' ? 'The Summary cannot be hidden: it is where the fields are' : undefined
                    }
                    onClick={() => onLayout(toggleTab(layout, row.id))}
                  />
                </li>
              )
            })}
          </ul>
          <p role="status" className="sr-only">
            {said}
          </p>
          <p className="text-xs text-fg-muted">
            Drag to order, or use the arrows. A page is a grid you arrange; a tab of Nik can be moved or hidden, not
            redrawn.
          </p>
        </section>

        <section aria-label="Other views of this type" className="flex flex-col gap-2 border border-line bg-panel p-3">
          <h3 className={CAPTION}>Other views of this type</h3>
          <ul className="flex flex-col gap-1">
            {[
              { view: 'close', label: 'Close form', tag: closeTag(layout) },
              { view: 'quick', label: 'Quick view', tag: quickTag(layout) },
            ].map((item) => (
              <li
                key={item.view}
                className={`${ROW} ${chosen.view === item.view ? 'border-accent-strong bg-raised' : 'border-line-soft bg-canvas'}`}
              >
                <button
                  type="button"
                  aria-pressed={chosen.view === item.view}
                  onClick={() => setChosen({ view: item.view })}
                  className="min-w-0 flex-1 truncate text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {item.label}
                </button>
                <span className={TAG}>{item.tag}</span>
              </li>
            ))}
          </ul>
          <p className="text-xs text-fg-muted">
            The close form is what the Close dialog asks. The quick view is the panel opened from a row of the incident
            list.
          </p>
        </section>
      </aside>

      {chosen.view === 'close' ? (
        <CloseFormEditor layout={layout} onLayout={onLayout} known={known} flags={type.fields} />
      ) : chosen.view === 'quick' ? (
        <QuickViewEditor layout={layout} onLayout={onLayout} />
      ) : (
        <TypePageEditor
          key={page ?? 'summary'}
          layout={layout}
          onLayout={onLayout}
          pageId={page}
          fields={typeFields}
          onDeleted={() => setChosen({ view: 'page', page: null })}
        />
      )}

      <Modal
        open={naming !== null}
        onClose={() => setNaming(null)}
        title="Add a page"
        footer={
          <>
            <Button variant="secondary" onClick={() => setNaming(null)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-page" disabled={!String(naming ?? '').trim()}>
              Add the page
            </Button>
          </>
        }
      >
        <form id="form-new-page" onSubmit={create} className="flex flex-col gap-2 text-sm">
          <label className="flex flex-col gap-1" htmlFor="new-page-name">
            <span className="text-fg-muted">Name</span>
            <input
              id="new-page-name"
              type="text"
              value={naming ?? ''}
              maxLength={PAGE_NAME_MAX}
              autoComplete="off"
              placeholder="Containment"
              onChange={(event) => setNaming(event.target.value)}
              className={INPUT}
            />
          </label>
          <p className="text-xs text-fg-muted">
            It is what the tab is called. The page starts empty, after the other tabs: add its widgets, and move its tab
            where it belongs.
          </p>
        </form>
      </Modal>
    </div>
  )
}
