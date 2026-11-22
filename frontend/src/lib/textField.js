/*
 * Text fields, as the right-click menu needs them: what is selected in one,
 * and cut, copy, paste, select all, undo and redo done to it.
 *
 * Three kinds of field are known: an <input> or a <textarea>, an element the
 * person edits in place (contenteditable), and a code editor, which keeps its
 * own text, selection and undo and says so here with registerEditor().
 *
 * Changes go through the browser's own editing commands, so the page that owns
 * the field hears them as typing and Ctrl Z undoes them. The clipboard is
 * written through copyText (lib/download.js), and read with the Clipboard API:
 * the browser may ask the person first, and may refuse.
 */

import { fieldKind } from '../domain/contextMenu.js'
import { copyText } from './download.js'

const editors = new WeakMap()

/**
 * A code editor says how it is edited. `dom` is its outermost element.
 *
 * @param {HTMLElement} dom
 * @param {{
 *   readOnly: () => boolean, text: () => string, selected: () => string,
 *   insert: (text: string) => void, selectAll: () => void, focus: () => void,
 *   undo: () => void, redo: () => void, canUndo: () => boolean, canRedo: () => boolean,
 * }} editor
 * @returns {() => void} forgets it
 */
export function registerEditor(dom, editor) {
  editors.set(dom, editor)
  return () => editors.delete(dom)
}

function editorAround(element) {
  for (let node = element; node instanceof Element; node = node.parentElement) {
    const editor = editors.get(node)
    if (editor) return { editor, dom: node }
  }
  return null
}

/**
 * The text field `element` is, or is inside of, with what the menu needs to
 * know about it now; null when it is not in one. What is selected is kept, so
 * the entry chosen later acts on it even though the menu took the focus.
 */
export function fieldAt(element) {
  if (!(element instanceof Element)) return null
  const code = editorAround(element)
  if (code) {
    const { editor, dom } = code
    const text = editor.text()
    return {
      kind: 'editor',
      element: dom,
      editor,
      readOnly: editor.readOnly(),
      secret: false,
      ranged: true,
      hasSelection: editor.selected() !== '',
      empty: text === '',
      history: { canUndo: editor.canUndo(), canRedo: editor.canRedo() },
    }
  }
  const input = element.closest('input, textarea')
  if (input) {
    const kind = fieldKind({ tag: input.tagName, type: input.getAttribute('type') ?? '' })
    if (!kind) return null
    let start = null
    let end = null
    if (kind.ranged) {
      try {
        start = input.selectionStart
        end = input.selectionEnd
      } catch {
        /* a type that keeps its selection to itself */
      }
    }
    const ranged = kind.ranged && start !== null && end !== null
    return {
      kind: 'input',
      element: input,
      readOnly: input.readOnly || input.disabled,
      secret: kind.secret,
      ranged,
      start,
      end,
      hasSelection: ranged && end > start,
      empty: input.value === '',
      history: null,
    }
  }
  const editable = element.closest('[contenteditable]:not([contenteditable="false"])')
  if (editable instanceof HTMLElement && editable.isContentEditable) {
    const selection = window.getSelection()
    const range =
      selection && selection.rangeCount > 0 && editable.contains(selection.getRangeAt(0).commonAncestorContainer)
        ? selection.getRangeAt(0).cloneRange()
        : null
    return {
      kind: 'editable',
      element: editable,
      readOnly: false,
      secret: false,
      ranged: true,
      range,
      hasSelection: Boolean(range && !range.collapsed),
      empty: editable.textContent === '',
      history: null,
    }
  }
  return null
}

/** The focus back in the field, with the selection it had when the menu opened. */
function restore(field) {
  const { element } = field
  if (field.kind === 'editor') {
    field.editor.focus()
    return
  }
  element.focus({ preventScroll: true })
  if (field.kind === 'input' && field.ranged) element.setSelectionRange(field.start, field.end)
  if (field.kind === 'editable' && field.range) {
    const selection = window.getSelection()
    selection.removeAllRanges()
    selection.addRange(field.range)
  }
}

/** What "Copy" takes: the selection, or the whole value of a field that does not say what is selected. */
export function selectedText(field) {
  if (field.kind === 'editor') return field.editor.selected()
  if (field.kind === 'editable') return field.range ? field.range.toString() : ''
  const { element } = field
  return field.ranged ? element.value.slice(field.start, field.end) : element.value
}

/** Put `text` in place of the selection (an empty text deletes it). */
function replaceSelection(field, text) {
  if (field.kind === 'editor') {
    field.editor.insert(text)
    return
  }
  restore(field)
  const { element } = field
  if (field.kind === 'input' && !field.ranged && text === '') element.select()
  // The browser's own command: the page hears typing, and Ctrl Z takes it back.
  const done = text === '' ? document.execCommand('delete') : document.execCommand('insertText', false, text)
  if (done || field.kind !== 'input') return
  // A browser without the command: the value is set as typing would, and the page is told.
  const from = field.ranged ? field.start : 0
  const to = field.ranged ? field.end : element.value.length
  const next = element.value.slice(0, from) + text + element.value.slice(to)
  const proto = element instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(element, next)
  if (field.ranged) element.setSelectionRange(from + text.length, from + text.length)
  element.dispatchEvent(new Event('input', { bubbles: true }))
}

/**
 * Do one entry of the menu of a text field. Resolves to what to tell the
 * person, or to null when there is nothing to say.
 *
 * @param {'undo' | 'redo' | 'cut' | 'copy' | 'paste' | 'selectAll'} id
 * @param {object} field  what fieldAt() returned
 * @returns {Promise<string | null>}
 */
export async function runFieldEntry(id, field) {
  if (id === 'undo' || id === 'redo') {
    field.editor?.[id]()
    field.editor?.focus()
    return null
  }
  if (id === 'selectAll') {
    if (field.kind === 'editor') field.editor.selectAll()
    else if (field.kind === 'input') {
      field.element.focus({ preventScroll: true })
      field.element.select()
    } else {
      field.element.focus({ preventScroll: true })
      window.getSelection().selectAllChildren(field.element)
    }
    return null
  }
  if (id === 'copy' || id === 'cut') {
    const copied = await copyText(selectedText(field))
    // The selection is shown again: it is what was copied.
    if (!copied || id === 'copy') restore(field)
    if (!copied) return 'The browser refused to copy.'
    if (id === 'cut') replaceSelection(field, '')
    return null
  }
  if (id === 'paste') {
    let text = null
    try {
      text = await navigator.clipboard.readText()
    } catch {
      /* refused by the person, by the browser, or not offered on this page */
    }
    if (text === null) {
      restore(field)
      return 'The browser did not let Nik read the clipboard. Press Ctrl V to paste.'
    }
    if (text === '') {
      restore(field)
      return 'There is no text in the clipboard.'
    }
    // A field of one line takes one line, as the browser's own paste does.
    const single = field.kind === 'input' && field.element instanceof HTMLInputElement
    replaceSelection(field, single ? text.replace(/[\r\n]+/g, ' ') : text)
    return null
  }
  return null
}
