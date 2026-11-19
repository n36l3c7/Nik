import { useEffect, useMemo, useState } from 'react'
import { Plus, RotateCcw } from 'lucide-react'
import { api } from '../../../services/api.js'
import { compactGrid } from '../../../domain/dashboards.js'
import {
  NOTE_MAX,
  PLAYBOOKS_MAX,
  WIDGET_KINDS,
  addWidget,
  canAdd,
  freeSections,
  gridOf,
  gridSections,
  kindOf,
  widgetTitle,
} from '../../../domain/layoutGrid.js'
import { Button, Modal } from '../../ui/index.js'
import Grid from '../../dashboards/Grid.jsx'
import { WidgetPreview } from '../../tabs/summary/LayoutWidgets.jsx'

/*
 * ============================================================================
 * THE PAGE OF A TYPE — the Summary of its incidents, arranged like a dashboard
 * ============================================================================
 *
 * The same grid as the dashboards: a widget is dragged by its grip, resized
 * by its corner, moved and resized with the arrow keys on the grip; the
 * others make room. "Add a widget" offers the kinds there are; the pencil of
 * a widget sets its title and what it shows (which section, which playbooks,
 * which text).
 *
 * A type that never arranged its page shows the one Nik makes from its
 * sections. The first change keeps the page as it is drawn then; "Back to the
 * generated page" lets Nik make it again.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{ layout: object, onLayout: (layout: object) => void }} props
 */
export default function TypePageEditor({ layout, onLayout }) {
  const { grid, custom } = useMemo(() => gridOf({ layout }), [layout])
  const [adding, setAdding] = useState('')
  const [editing, setEditing] = useState(null) // the widget in the form
  const [said, setSaid] = useState('')
  const [playbooks, setPlaybooks] = useState(null) // null: not read yet; false: may not be read

  const setGrid = (next) => onLayout({ ...layout, grid: next })
  const byId = useMemo(() => new Map(grid.map((widget) => [widget.id, widget])), [grid])
  // The grid of the dashboards names a widget by its title and its type.
  const drawn = useMemo(
    () => grid.map((widget) => ({ ...widget, type: widget.kind, title: widgetTitle(widget, layout) })),
    [grid, layout],
  )
  /** What the grid gives back after a move, as the layout keeps it: without what was added to draw it. */
  const kept = (widgets) =>
    widgets.map((widget) => ({ ...byId.get(widget.id), x: widget.x, y: widget.y, w: widget.w, h: widget.h }))

  const free = freeSections(grid, layout)
  const offered = WIDGET_KINDS.filter((kind) => canAdd(grid, kind.id) && (kind.id !== 'section' || free.length > 0))

  const add = () => {
    if (!adding) return
    const extras = adding === 'section' ? { section: free[0]?.id } : {}
    const next = addWidget(grid, adding, extras)
    setGrid(next)
    setSaid(`${kindOf(adding).label} was added at the bottom of the page.`)
    setAdding('')
  }

  // The playbooks, for the buttons: read when a widget of buttons is opened.
  useEffect(() => {
    if (editing?.kind !== 'playbooks' || playbooks !== null) return undefined
    let alive = true
    api
      .get('/automation/playbooks')
      .then((found) => alive && setPlaybooks(found.playbooks))
      .catch(() => alive && setPlaybooks(false))
    return () => {
      alive = false
    }
  }, [editing, playbooks])

  const saveEdited = (event) => {
    event.preventDefault()
    setGrid(grid.map((widget) => (widget.id === editing.id ? editing : widget)))
    setEditing(null)
  }

  return (
    <section aria-label="The page" className="flex flex-col gap-3 border border-line bg-panel p-3">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">The page</h3>
          <p className="text-sm text-fg-muted">
            The Summary of an incident of this type, on twelve columns. Drag a widget by its grip, resize it by its
            corner. {custom ? 'This page was arranged by hand.' : 'This is the page Nik makes from the sections.'}
          </p>
        </div>
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
        {custom && (
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
      </div>
      {adding && <p className="text-xs text-fg-muted">{kindOf(adding)?.hint}</p>}
      <p role="status" className="sr-only">
        {said}
      </p>
      <Grid
        widgets={drawn}
        editing
        onChange={(next) => setGrid(kept(next))}
        onEdit={(widget) => setEditing({ ...byId.get(widget.id) })}
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
        render={(widget) => <WidgetPreview widget={byId.get(widget.id) ?? widget} layout={layout} />}
      />

      <Modal
        open={editing !== null}
        onClose={() => setEditing(null)}
        title={editing ? `Widget: ${kindOf(editing.kind)?.label}` : 'Widget'}
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
                  The fields of a section are chosen above, where the sections are.
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
            {editing.kind === 'playbooks' && (
              <fieldset className="flex flex-col gap-1 text-sm">
                <legend className="mb-1 text-fg-muted">Playbooks, {PLAYBOOKS_MAX} at most</legend>
                {playbooks === null && <p className="font-mono text-xs text-fg-muted">Loading…</p>}
                {playbooks === false && (
                  <p className="text-xs text-fg-muted">Your roles do not include reading the playbooks.</p>
                )}
                {Array.isArray(playbooks) && playbooks.length === 0 && (
                  <p className="text-xs text-fg-muted">There is no playbook yet.</p>
                )}
                {Array.isArray(playbooks) &&
                  playbooks.map((playbook) => {
                    const chosen = (editing.playbooks ?? []).includes(playbook.id)
                    return (
                      <label key={playbook.id} className="flex items-center gap-2 text-fg">
                        <input
                          type="checkbox"
                          checked={chosen}
                          disabled={!chosen && (editing.playbooks ?? []).length >= PLAYBOOKS_MAX}
                          onChange={(event) =>
                            setEditing({
                              ...editing,
                              playbooks: event.target.checked
                                ? [...(editing.playbooks ?? []), playbook.id]
                                : (editing.playbooks ?? []).filter((id) => id !== playbook.id),
                            })
                          }
                          className="accent-accent"
                        />
                        {playbook.name}
                        {!playbook.version && <span className="text-xs text-fg-muted">· no version yet</span>}
                      </label>
                    )
                  })}
              </fieldset>
            )}
          </form>
        )}
      </Modal>
    </section>
  )
}
