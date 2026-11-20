/*
 * The right-click menu of the playbook editor: what it offers on a node, on
 * several selected nodes, on a line and on the empty canvas.
 *
 * It is the menu every list of Nik has (context/ContextMenuContext.jsx), with
 * the same sections in the same order: what the thing does, what copies it,
 * what changes around it, and last, after a rule, what deletes it. This is the
 * part that can be checked without a browser: which entries there are, the
 * key that does the same, and why an entry cannot be done here. The canvas
 * gives each entry what it runs (components/automation/useEditorMenu.js).
 */
import { joinSections } from '../menus.js'
import { MAX_NODES, linesOf, nodeOf, portLabel } from './graph.js'

/** The keys that do what an entry does, as the menu shows them. */
export const SHORTCUTS = {
  open: 'enter',
  duplicate: 'ctrl d',
  copy: 'ctrl c',
  cut: 'ctrl x',
  paste: 'ctrl v',
  remove: 'del',
  selectAll: 'ctrl a',
  undo: 'ctrl z',
  redo: 'ctrl shift z',
}

const entry = (id, label, why = null) => ({
  id,
  label,
  ...(SHORTCUTS[id] ? { hint: SHORTCUTS[id] } : {}),
  // An entry that cannot be done stays in the menu, and says why when it is pointed at.
  ...(why ? { disabled: true, title: why } : {}),
})

const FULL = `A playbook has at most ${MAX_NODES} nodes`

/**
 * The menu of what was right-clicked: `{ title, items }`, the items being
 * `{ id, label, hint?, disabled?, title? }` or 'separator'.
 *
 * @param {{ kind: 'node', id: string } | { kind: 'selection', ids: string[] }
 *   | { kind: 'edge', from: string, port: string, to: string } | { kind: 'pane' }} target
 * @param {{
 *   graph: object,
 *   readOnly?: string | null,   // why nothing can be changed here (somebody else's branch…), or null
 *   copied?: number,            // how many nodes "copy" holds
 *   canUndo?: boolean, canRedo?: boolean,
 *   canDebug?: boolean,         // this account may start a debug run of what is on the canvas
 * }} state
 */
export function editorMenu(target, state) {
  const { graph, readOnly = null, copied = 0, canUndo = false, canRedo = false, canDebug = false } = state
  const count = graph.nodes.length

  if (target.kind === 'edge') {
    const label = portLabel(nodeOf(graph, target.from), target.port)
    const name = (id) => nodeOf(graph, id)?.name || id
    return {
      title: `${name(target.from)} → ${name(target.to)}${label ? ` · ${label}` : ''}`,
      items: joinSections([[{ ...entry('removeLine', 'Delete this connection', readOnly), hint: SHORTCUTS.remove }]]),
    }
  }

  if (target.kind === 'pane') {
    return {
      title: readOnly ? 'The canvas · read-only' : 'The canvas',
      items: joinSections([
        [
          entry('add', 'Add a node here…', readOnly ?? (count >= MAX_NODES ? FULL : null)),
          entry(
            'paste',
            'Paste here',
            readOnly ?? (copied === 0 ? 'Nothing was copied yet' : count + copied > MAX_NODES ? FULL : null),
          ),
        ],
        [entry('selectAll', 'Select all'), entry('fit', 'Fit the view'), entry('tidy', 'Tidy up', readOnly)],
        [
          entry('undo', 'Undo', readOnly ?? (canUndo ? null : 'Nothing to undo')),
          entry('redo', 'Redo', readOnly ?? (canRedo ? null : 'Nothing to redo')),
        ],
      ]),
    }
  }

  const ids = (target.kind === 'node' ? [target.id] : target.ids).filter((id) => nodeOf(graph, id))
  const several = ids.length > 1
  const node = several ? null : nodeOf(graph, ids[0])
  // The trigger is the one node a playbook always has, and has once: it is not copied or deleted.
  const others = ids.filter((id) => nodeOf(graph, id).kind !== 'trigger')
  const onlyTrigger = others.length === 0
  const lines = linesOf(graph, ids)
  const its = several ? 'their' : 'its'
  const title = several ? `${ids.length} nodes` : node?.name || node?.id || ''

  return {
    title: readOnly ? `${title} · read-only` : title,
    items: joinSections([
      [
        !several && entry('open', 'Open in the inspector'),
        canDebug &&
          entry(
            'debug',
            several ? 'Debug, stopping before them…' : 'Debug, stopping before it…',
            onlyTrigger ? 'A run starts at its trigger: choose a node after it to stop before' : null,
          ),
      ],
      [
        entry(
          'duplicate',
          'Duplicate',
          readOnly ?? (onlyTrigger ? 'A playbook has one trigger' : count + others.length > MAX_NODES ? FULL : null),
        ),
        entry('copy', 'Copy', onlyTrigger ? 'A playbook has one trigger: it is not copied' : null),
        entry('cut', 'Cut', readOnly ?? (onlyTrigger ? 'A playbook keeps its trigger' : null)),
      ],
      [
        entry(
          'disconnect',
          `Disconnect ${its} lines`,
          readOnly ??
            (lines === 0 ? `No line arrives at ${several ? 'them' : 'it'} or leaves ${several ? 'them' : 'it'}` : null),
        ),
      ],
      [entry('remove', 'Delete', readOnly ?? (onlyTrigger ? 'A playbook keeps its trigger' : null))],
    ]),
  }
}
