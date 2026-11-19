import { useEffect, useMemo, useState } from 'react'
import { Plus, RotateCcw, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import { compactGrid } from '../../../domain/dashboards.js'
import {
  NOTE_MAX,
  WIDGET_KINDS,
  addWidget,
  canAdd,
  drawnWidgets,
  freeSections,
  gridOf,
  gridSections,
  kindOf,
  widgetTitle,
} from '../../../domain/layoutGrid.js'
import { PAGE_NAME_MAX, pageName, pageOf, removePage, renamePage, setPageGrid } from '../../../domain/typePages.js'
import { Button, Modal } from '../../ui/index.js'
import Grid from '../../dashboards/Grid.jsx'
import { WidgetPreview } from '../../tabs/summary/LayoutWidgets.jsx'
import { ButtonsSettings, ChartSettings, buttonsProblem } from './WidgetSettings.jsx'

/*
 * ============================================================================
 * A PAGE OF A TYPE — the Summary of its incidents, or a page of its own,
 * arranged like a dashboard
 * ============================================================================
 *
 * The same grid as the dashboards: a widget is dragged by its grip, resized
 * by its corner, moved and resized with the arrow keys on the grip; the
 * others make room. "Add a widget" offers the kinds there are; the pencil of
 * a widget sets its title and what it shows (which section, which text, which
 * buttons, which chart).
 *
 * The Summary of a type that never arranged it is the page Nik makes from
 * its sections. The first change keeps the page as it is drawn then; "Back
 * to the generated page" lets Nik make it again. A page of the type's own
 * (6.2) starts empty, has a name, which is what its tab is called, and can be
 * deleted.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   layout: object,
 *   onLayout: (layout: object) => void,
 *   pageId?: string | null,          // the page of the type to arrange; the Summary when left out
 *   fields?: object[],               // the fields of the type, for the templates of script buttons
 *   onDeleted?: () => void,          // after the page was deleted
 * }} props
 */
export default function TypePageEditor({ layout, onLayout, pageId = null, fields = [], onDeleted = null }) {
  const page = pageId ? pageOf(layout, pageId) : null
  const { grid, custom } = useMemo(
    () => (pageId ? { grid: pageOf(layout, pageId)?.grid ?? [], custom: true } : gridOf({ layout })),
    [layout, pageId],
  )
  const [adding, setAdding] = useState('')
  const [editing, setEditing] = useState(null) // the widget in the form
  const [problem, setProblem] = useState(null)
  const [said, setSaid] = useState('')
  const [boards, setBoards] = useState(null) // the dashboards, to name the chart a widget shows
  const [deleting, setDeleting] = useState(false)

  const setGrid = (next) => onLayout(pageId ? setPageGrid(layout, pageId, next) : { ...layout, grid: next })
  const byId = useMemo(() => new Map(grid.map((widget) => [widget.id, widget])), [grid])
  const drawn = useMemo(() => drawnWidgets(grid, layout), [grid, layout])
  /** What the grid gives back after a move, as the layout keeps it: without what was added to draw it. */
  const kept = (widgets) =>
    widgets.map((widget) => ({ ...byId.get(widget.id), x: widget.x, y: widget.y, w: widget.w, h: widget.h }))

  const free = freeSections(grid, layout)
  const offered = WIDGET_KINDS.filter((kind) => canAdd(grid, kind.id) && (kind.id !== 'section' || free.length > 0))
  const name = page ? pageName(page) : 'Summary'

  const add = () => {
    if (!adding) return
    const extras = adding === 'section' ? { section: free[0]?.id } : {}
    const next = addWidget(grid, adding, extras)
    setGrid(next)
    setSaid(`${kindOf(adding).label} was added at the bottom of the page.`)
    setAdding('')
  }

  // The dashboards, with their widgets: read when the page shows a chart, to say which.
  const charts = grid.some((widget) => widget.kind === 'chart')
  useEffect(() => {
    if (!charts || boards !== null) return undefined
    let alive = true
    api
      .get('/dashboards')
      .then((found) =>
        Promise.all(
          found.dashboards.map((board) =>
            api.get(`/dashboards/${encodeURIComponent(board.id)}`).catch(() => ({ ...board, widgets: [] })),
          ),
        ),
      )
      .then((found) => alive && setBoards(found))
      .catch(() => alive && setBoards([]))
    return () => {
      alive = false
    }
  }, [charts, boards])

  const saveEdited = (event) => {
    event.preventDefault()
    const wrong = editing.kind === 'buttons' ? buttonsProblem(editing.buttons) : null
    if (wrong) {
      setProblem(wrong)
      return
    }
    setGrid(grid.map((widget) => (widget.id === editing.id ? editing : widget)))
    setEditing(null)
  }
  const edit = (widget) => {
    setProblem(null)
    setEditing(widget)
  }

  if (pageId && !page) return null
  return (
    <section aria-label="The page" className="flex min-w-0 flex-col gap-3 border border-line bg-panel p-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Page: {name}</h3>
          <p className="text-sm text-fg-muted">
            {page ? 'A page of this type, shown as a tab of its incidents' : 'The Summary of an incident of this type'},
            on twelve columns. Drag a widget by its grip, resize it by its corner.{' '}
            {page ? '' : custom ? 'This page was arranged by hand.' : 'This is the page Nik makes from the sections.'}
          </p>
        </div>
        {page && (
          <label className="flex flex-col gap-1 text-xs text-fg-muted" htmlFor="page-name">
            Name
            <input
              id="page-name"
              type="text"
              value={page.name}
              maxLength={PAGE_NAME_MAX}
              autoComplete="off"
              onChange={(event) => onLayout(renamePage(layout, pageId, event.target.value))}
              className={`${INPUT} w-48`}
            />
          </label>
        )}
        <label className="flex flex-col gap-1 text-xs text-fg-muted" htmlFor="page-add-kind">
          Add a widget
          <span className="flex gap-2">
            <select
              id="page-add-kind"
              value={adding}
              onChange={(event) => setAdding(event.target.value)}
              className={`${INPUT} w-56 cursor-pointer`}
            >
              <option value="">Choose a kind…</option>
              {offered.map((kind) => (
                <option key={kind.id} value={kind.id} title={kind.hint}>
                  {kind.label}
                </option>
              ))}
            </select>
            <Button variant="secondary" size="sm" icon={Plus} disabled={!adding} onClick={add}>
              Add
            </Button>
          </span>
        </label>
        {!page && custom && (
          <Button
            variant="ghost"
            size="sm"
            icon={RotateCcw}
            title="Forget this arrangement: Nik makes the page from the sections again"
            onClick={() => {
              const { grid: _gone, ...rest } = layout
              onLayout(rest)
              setSaid('The page is the generated one again.')
            }}
          >
            Back to the generated page
          </Button>
        )}
        {page && (
          <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setDeleting(true)}>
            Delete the page…
          </Button>
        )}
      </div>
      {adding && <p className="text-xs text-fg-muted">{kindOf(adding)?.hint}</p>}
      <p role="status" className="sr-only">
        {said}
      </p>
      {grid.length === 0 && (
        <p className="border border-dashed border-line px-3 py-6 text-center text-sm text-fg-muted">
          Nothing on this page yet: add a widget.
        </p>
      )}
      {/* Arranged on its twelve columns whatever the room: under 860 px the grid would be one column, with nothing to drag. */}
      <div className="overflow-x-auto">
        <div className="min-w-[860px]">
          <Grid
            widgets={drawn}
            editing
            onChange={(next) => setGrid(kept(next))}
            onEdit={(widget) => edit({ ...byId.get(widget.id) })}
            onDuplicate={(widget) => {
              const source = byId.get(widget.id)
              if (!canAdd(grid, source.kind) || source.kind === 'section') {
                setSaid(`${widgetTitle(source, layout)} is on a page once.`)
                return
              }
              const { id: _id, x: _x, y: _y, ...copied } = source
              setGrid(addWidget(grid, source.kind, copied))
            }}
            onRemove={(widget) => setGrid(compactGrid(grid.filter((item) => item.id !== widget.id)))}
            render={(widget) => (
              <WidgetPreview widget={byId.get(widget.id) ?? widget} layout={layout} boards={boards} />
            )}
          />
        </div>
      </div>

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing ? `Widget: ${kindOf(editing.kind)?.label}` : 'Widget'}
        maxWidth={editing?.kind === 'buttons' ? 'max-w-2xl' : 'max-w-lg'}
        footer={
          <>
            <Button variant="secondary" onClick={() => setEditing(null)}>
              Cancel
            </Button>
            <Button type="submit" form="form-page-widget">
              Done
            </Button>
          </>
        }
      >
        {editing && (
          <form id="form-page-widget" onSubmit={saveEdited} className="flex flex-col gap-3">
            <label className="flex flex-col gap-1 text-sm" htmlFor="widget-title">
              <span className="text-fg-muted">Title</span>
              <input
                id="widget-title"
                type="text"
                value={editing.title ?? ''}
                maxLength={80}
                autoComplete="off"
                placeholder={widgetTitle({ ...editing, title: '' }, layout)}
                onChange={(event) => setEditing({ ...editing, title: event.target.value })}
                className={INPUT}
              />
              <span className="text-xs text-fg-muted">Left empty, the widget is called by what it shows.</span>
            </label>
            {editing.kind === 'section' && (
              <label className="flex flex-col gap-1 text-sm" htmlFor="widget-section">
                <span className="text-fg-muted">Section</span>
                <select
                  id="widget-section"
                  value={editing.section}
                  onChange={(event) => setEditing({ ...editing, section: event.target.value })}
                  className={`${INPUT} cursor-pointer`}
                >
                  {gridSections(layout)
                    .filter((section) => section.id === editing.section || free.some((item) => item.id === section.id))
                    .map((section) => (
                      <option key={section.id} value={section.id}>
                        {section.title}
                      </option>
                    ))}
                </select>
                <span className="text-xs text-fg-muted">
                  The fields of a section are chosen under “Fields and sections”.
                </span>
              </label>
            )}
            {editing.kind === 'note' && (
              <label className="flex flex-col gap-1 text-sm" htmlFor="widget-text">
                <span className="text-fg-muted">Text</span>
                <textarea
                  id="widget-text"
                  value={editing.text ?? ''}
                  rows={5}
                  maxLength={NOTE_MAX}
                  onChange={(event) => setEditing({ ...editing, text: event.target.value })}
                  className={`${INPUT} resize-y`}
                />
              </label>
            )}
            {editing.kind === 'buttons' && (
              <ButtonsSettings
                buttons={editing.buttons ?? []}
                fields={fields}
                onChange={(buttons) => {
                  setProblem(null)
                  setEditing({ ...editing, buttons })
                }}
              />
            )}
            {editing.kind === 'chart' && (
              <ChartSettings widget={editing} onChange={(changes) => setEditing({ ...editing, ...changes })} />
            )}
            {problem && (
              <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
                {problem}
              </p>
            )}
          </form>
        )}
      </Modal>

      <Modal
        open={deleting}
        onClose={() => setDeleting(false)}
        title={`Delete the page ${name}?`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleting(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => {
                setDeleting(false)
                onLayout(removePage(layout, pageId))
                onDeleted?.()
              }}
            >
              Delete the page
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          Its tab leaves the incidents of this type when the type is saved. What the widgets showed stays where it is: a
          page only arranges it.
        </p>
      </Modal>
    </section>
  )
}
