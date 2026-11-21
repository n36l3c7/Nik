import {
  ArrowLeft,
  ClipboardPaste,
  Copy,
  Crosshair,
  Download,
  ExternalLink,
  Keyboard,
  Link2,
  ListPlus,
  Redo2,
  Scissors,
  Search,
  SquareArrowOutUpRight,
  TextSelect,
  Undo2,
} from 'lucide-react'
import { fieldItems, generalItems, linkItems, selectionItems, textItems } from '../../domain/contextMenu.js'
import { copyText } from '../../lib/download.js'
import { runFieldEntry } from '../../lib/textField.js'

/*
 * The sections of the right-click menu that belong to no page: selected text,
 * a text field, a link, a cell or a line of text, and the general section that
 * ends every menu. domain/contextMenu.js says which entries there are; here
 * each one gets its icon and what it runs.
 *
 * `app` is what the application lends (useAmbientMenu, called by App): who is
 * signed in and what they may do, how the search and the list of shortcuts
 * open, how an indicator is looked up and added. Before anybody is signed in
 * it is empty, and the menu holds what needs nobody: back, the address.
 */

const ICONS = {
  undo: Undo2,
  redo: Redo2,
  cut: Scissors,
  copy: Copy,
  paste: ClipboardPaste,
  selectAll: TextSelect,
  copySelection: Copy,
  copyCell: Copy,
  copyRow: Copy,
  copyText: Copy,
  whereSeen: Crosshair,
  searchFor: Search,
  addIndicator: ListPlus,
  followLink: ExternalLink,
  openLinkTab: SquareArrowOutUpRight,
  copyLink: Link2,
  search: Search,
  shortcuts: Keyboard,
  back: ArrowLeft,
  copyAddress: Link2,
}

/**
 * The items of one section.
 *
 * @param {'selection' | 'field' | 'link' | 'text' | 'general'} kind
 * @param {object} under  what lib/underPointer.js found
 * @param {object} app    what the application lends (see above)
 * @param {(message: string) => void} say  tells the person something in a toast
 */
export function ambientItems(kind, under, app, say) {
  const rights = { canRead: Boolean(app.signedIn && app.canRead), canWrite: Boolean(app.signedIn && app.canWrite) }
  const copy = async (text, what) => say((await copyText(text)) ? `${what} copied.` : 'The browser refused to copy.')
  const lookup = (item) => ({
    whereSeen: () => app.openIoc?.(item.match.kind, item.match.value),
    searchFor: () => app.openSearch?.(item.match.value),
    addIndicator: () => app.addIndicator?.(item.match.value),
  })

  let items = []
  let run = () => ({})
  if (kind === 'selection') {
    items = selectionItems(under.selection, rights)
    run = (item) => ({ copySelection: () => copy(under.selection, 'Text'), ...lookup(item) })
  } else if (kind === 'field') {
    const { field } = under
    items = fieldItems(field)
    run = (item) => ({
      [item.id]: async () => {
        const message = await runFieldEntry(item.id, field)
        if (message) say(message)
      },
    })
  } else if (kind === 'text') {
    const found = under.text
    items = textItems(found, rights)
    run = (item) => ({
      copyCell: () => copy(found.cell, 'Cell'),
      copyRow: () => copy(found.row, 'Row'),
      copyText: () => copy(found.text, 'Text'),
      ...lookup(item),
    })
  } else if (kind === 'link') {
    const { link } = under
    items = linkItems(link, window.location.origin)
    run = () => ({
      followLink: () => link.element.click(),
      openLinkTab: () => window.open(link.href, '_blank', 'noopener,noreferrer'),
      copyLink: () => copy(link.href, 'Address'),
    })
  } else if (kind === 'general') {
    items = generalItems({
      signedIn: Boolean(app.signedIn),
      canRead: Boolean(app.canRead),
      canGoBack: window.history.length > 1,
      shortcuts: Boolean(app.openShortcuts),
    })
    run = () => ({
      search: () => app.openSearch?.(''),
      shortcuts: () => app.openShortcuts?.(),
      back: () => window.history.back(),
      copyAddress: () => copy(window.location.href, 'Address'),
    })
  }

  return items.map((item) => {
    if (item === 'separator') return item
    const { id, match: _match, ...shown } = item
    const icon = id === 'followLink' && item.label === 'Download' ? Download : ICONS[id]
    return { ...shown, icon, onSelect: run(item)[id] }
  })
}
