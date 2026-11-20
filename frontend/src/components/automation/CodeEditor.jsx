import { useEffect, useRef } from 'react'
import { Compartment, EditorState } from '@codemirror/state'
import {
  EditorView,
  drawSelection,
  highlightActiveLine,
  highlightActiveLineGutter,
  keymap,
  lineNumbers,
} from '@codemirror/view'
import {
  defaultKeymap,
  history,
  historyKeymap,
  indentWithTab,
  redo,
  redoDepth,
  undo,
  undoDepth,
} from '@codemirror/commands'
import { HighlightStyle, bracketMatching, indentOnInput, indentUnit, syntaxHighlighting } from '@codemirror/language'
import { python } from '@codemirror/lang-python'
import { json } from '@codemirror/lang-json'
import { tags } from '@lezer/highlight'
import { registerEditor } from '../../lib/textField.js'

/*
 * ============================================================================
 * CODE EDITOR — CodeMirror 6, drawn as Nik
 * ============================================================================
 *
 * Python for scripts, JSON for their tests. The colours are Nik's tokens
 * (index.css), the font its monospace, the corners square. Line numbers, the
 * usual keys, undo of its own, Tab indents (Escape then Tab leaves the
 * editor, as CodeMirror does for keyboard users). The right-click menu cuts,
 * copies, pastes and undoes through what the editor says of itself here
 * (lib/textField.js).
 *
 * The parent owns the text: `value` is written into the editor when it
 * differs from what the editor holds (a version restored, another script
 * opened), and `onChange` reports what is typed.
 */

const theme = EditorView.theme(
  {
    '&': {
      color: 'var(--color-fg)',
      backgroundColor: 'var(--color-sunken)',
      border: '1px solid var(--color-line)',
      fontSize: '13px',
    },
    '&.cm-focused': { outline: '2px solid var(--color-accent)', outlineOffset: '-1px' },
    '.cm-scroller': { fontFamily: 'var(--font-mono)', lineHeight: '1.55' },
    '.cm-content': { caretColor: 'var(--color-accent)', padding: '8px 0' },
    '.cm-cursor, .cm-dropCursor': { borderLeftColor: 'var(--color-accent)' },
    '&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection':
      { backgroundColor: 'var(--color-info-soft)' },
    '.cm-gutters': {
      backgroundColor: 'var(--color-sunken)',
      color: 'var(--color-fg-subtle)',
      border: 'none',
      borderRight: '1px solid var(--color-line-soft)',
    },
    '.cm-activeLine': { backgroundColor: 'color-mix(in srgb, var(--color-raised) 55%, transparent)' },
    '.cm-activeLineGutter': { backgroundColor: 'transparent', color: 'var(--color-fg-muted)' },
    '.cm-matchingBracket, &.cm-focused .cm-matchingBracket': {
      backgroundColor: 'var(--color-accent-soft)',
      outline: '1px solid var(--color-accent-strong)',
    },
  },
  { dark: true },
)

const highlight = HighlightStyle.define([
  {
    tag: [tags.keyword, tags.controlKeyword, tags.operatorKeyword, tags.definitionKeyword],
    color: 'var(--color-info)',
  },
  { tag: [tags.string, tags.special(tags.string)], color: 'var(--color-accent-fg)' },
  { tag: [tags.number, tags.bool, tags.null], color: 'var(--color-med)' },
  { tag: [tags.comment, tags.lineComment], color: 'var(--color-fg-subtle)', fontStyle: 'italic' },
  {
    tag: [tags.function(tags.variableName), tags.function(tags.definition(tags.variableName))],
    color: 'var(--color-violet)',
  },
  { tag: [tags.className, tags.typeName], color: 'var(--color-violet)' },
  { tag: tags.propertyName, color: 'var(--color-link-fg)' },
  { tag: [tags.operator, tags.punctuation, tags.bracket], color: 'var(--color-fg-muted)' },
  { tag: tags.invalid, color: 'var(--color-high)' },
])

const LANGUAGES = { python, json }

/**
 * @param {{
 *   value: string,
 *   onChange?: (value: string) => void,
 *   language?: 'python' | 'json',
 *   readOnly?: boolean,
 *   label: string,                 // the accessible name of the editor
 *   minHeight?: string,
 *   maxHeight?: string,
 * }} props
 */
export default function CodeEditor({
  value,
  onChange,
  language = 'python',
  readOnly = false,
  label,
  minHeight = '8rem',
  maxHeight = '60vh',
}) {
  const host = useRef(null)
  const view = useRef(null)
  const onChangeRef = useRef(onChange)
  onChangeRef.current = onChange
  const editable = useRef(new Compartment())

  useEffect(() => {
    const state = EditorState.create({
      doc: value ?? '',
      extensions: [
        lineNumbers(),
        highlightActiveLineGutter(),
        highlightActiveLine(),
        history(),
        drawSelection(),
        indentOnInput(),
        bracketMatching(),
        indentUnit.of('    '),
        EditorState.tabSize.of(4),
        keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
        (LANGUAGES[language] ?? python)(),
        syntaxHighlighting(highlight),
        theme,
        EditorView.contentAttributes.of({ 'aria-label': label, spellcheck: 'false' }),
        editable.current.of([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
        EditorView.updateListener.of((update) => {
          if (update.docChanged) onChangeRef.current?.(update.state.doc.toString())
        }),
      ],
    })
    const made = new EditorView({ state, parent: host.current })
    view.current = made
    const selected = () =>
      made.state.selection.ranges
        .filter((range) => !range.empty)
        .map((range) => made.state.sliceDoc(range.from, range.to))
        .join(made.state.lineBreak)
    const forget = registerEditor(host.current, {
      readOnly: () => made.state.readOnly,
      text: () => made.state.doc.toString(),
      selected,
      insert: (text) => {
        made.dispatch(made.state.replaceSelection(text), { scrollIntoView: true, userEvent: 'input' })
        made.focus()
      },
      selectAll: () => {
        made.dispatch({ selection: { anchor: 0, head: made.state.doc.length } })
        made.focus()
      },
      focus: () => made.focus(),
      undo: () => undo(made),
      redo: () => redo(made),
      canUndo: () => undoDepth(made.state) > 0,
      canRedo: () => redoDepth(made.state) > 0,
    })
    return () => {
      forget()
      view.current.destroy()
      view.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the editor is made once; what changes is applied below
  }, [language, label])

  // The parent's text, when it is not what the editor holds already.
  useEffect(() => {
    const current = view.current
    if (!current) return
    const text = value ?? ''
    if (text !== current.state.doc.toString()) {
      current.dispatch({ changes: { from: 0, to: current.state.doc.length, insert: text } })
    }
  }, [value])

  useEffect(() => {
    view.current?.dispatch({
      effects: editable.current.reconfigure([EditorState.readOnly.of(readOnly), EditorView.editable.of(!readOnly)]),
    })
  }, [readOnly])

  return (
    <div ref={host} className="nik-code min-w-0" style={{ '--nik-code-min': minHeight, '--nik-code-max': maxHeight }} />
  )
}
