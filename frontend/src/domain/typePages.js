/*
 * The pages of a type of incident (6.2): its tabs in their order, the pages it
 * adds, the form its incidents are closed with and its quick view.
 *
 * Beside its sections and the grid of the Summary (domain/layoutGrid.js) a
 * layout keeps
 *
 *   tabs:   [ids]                     the order of the tabs; a page is 'page:<id>'
 *   hidden: [ids]                     the tabs that are not shown
 *   pages:  [{ id, name, grid }]      the pages of its own, ten at most
 *   close:  { sections: [ids] }       the sections the form of closing shows
 *   quick:  [{ kind, section?, text? }]   the blocks of the quick view
 *
 * A tab of Nik is moved or hidden, never redrawn; the Summary is never
 * hidden; a page of the type is a name and a grid, renamed and deleted at
 * will. Every edit here returns a new layout and leaves the one it was given
 * as it was. What draws the quick view is domain/quickView.js; what is here
 * is its editing.
 */
import { NOTE_MAX, cleanGrid, gridSections } from './layoutGrid.js'
import { QUICK_KINDS, QUICK_MAX } from './quickView.js'

export const PAGES_MAX = 10
export const PAGE_PREFIX = 'page:'
export const PAGE_NAME_MAX = 40
const PAGE_ID = /^[a-z][a-z0-9-]{0,31}$/

const list = (value) => (Array.isArray(value) ? value : [])

/** The id of the tab of a page, and the page a tab id names (null for a tab of Nik). */
export const pageTabId = (pageId) => `${PAGE_PREFIX}${pageId}`
export const pageIdOf = (tabId) =>
  String(tabId ?? '').startsWith(PAGE_PREFIX) ? tabId.slice(PAGE_PREFIX.length) : null

/**
 * The pages of a layout: each with an id that can be one, its name as it was
 * typed (`pageName` is what it is called) and its grid cleaned.
 */
export function pagesOf(layout) {
  const seen = new Set()
  const out = []
  for (const raw of list(layout?.pages).slice(0, PAGES_MAX)) {
    const id = String(raw?.id ?? '')
    if (!PAGE_ID.test(id) || seen.has(id)) continue
    seen.add(id)
    out.push({ id, name: String(raw.name ?? '').slice(0, PAGE_NAME_MAX), grid: cleanGrid(raw.grid, layout) })
  }
  return out
}

/** What a page is called on its tab: its name, or "Page" while it has none. */
export const pageName = (page) => String(page?.name ?? '').trim() || 'Page'

/** The page of a layout with that id (null when it has none). */
export const pageOf = (layout, pageId) => pagesOf(layout).find((page) => page.id === pageId) ?? null

/**
 * The tabs of the bar as a type orders them, the hidden ones in their place:
 * `{ id, label, kind, hidden }` where `kind` is 'summary', 'nik' (a tab of
 * Nik) or 'page' (a page of the type). `barTabs` are the tabs of Nik that are
 * on the bar (`{ id, label }`, config/tabs.js without the kinds of evidence).
 * The order is the one the incident page draws (`orderTabs`): the tabs the
 * layout names first, then the others as they come, the pages last.
 */
export function tabRows(layout, barTabs) {
  const hidden = new Set(list(layout?.hidden).filter((id) => id !== 'summary'))
  const all = [
    ...list(barTabs).map((tab) => ({ id: tab.id, label: tab.label, kind: tab.id === 'summary' ? 'summary' : 'nik' })),
    ...pagesOf(layout).map((page) => ({ id: pageTabId(page.id), label: pageName(page), kind: 'page' })),
  ]
  const named = list(layout?.tabs)
    .map((id) => all.find((tab) => tab.id === id))
    .filter(Boolean)
  const rest = all.filter((tab) => !named.includes(tab))
  return [...named, ...rest].map((tab) => ({ ...tab, hidden: hidden.has(tab.id) }))
}

/** What the tag of a row says: what kind of tab it is, and whether it is hidden. */
export function tabTag(row) {
  const what = row.kind === 'summary' ? 'page' : row.kind === 'page' ? 'page · yours' : 'Nik'
  return row.hidden ? `${what} · hidden` : what
}

/** `tabs` of a layout for the bar in the order given, keeping what it says of the kinds of evidence. */
function withBarOrder(layout, barTabs, ids) {
  const bar = new Set(tabRows(layout, barTabs).map((row) => row.id))
  const others = list(layout?.tabs).filter((id) => !bar.has(id))
  return { ...layout, tabs: [...ids, ...others] }
}

/** Move a tab of the bar one place up (`by` -1) or down (+1). Unchanged at the edges. */
export function moveTab(layout, barTabs, tabId, by) {
  const ids = tabRows(layout, barTabs).map((row) => row.id)
  const from = ids.indexOf(tabId)
  const to = from + by
  if (from < 0 || to < 0 || to >= ids.length) return layout
  ids.splice(to, 0, ...ids.splice(from, 1))
  return withBarOrder(layout, barTabs, ids)
}

/** Put a tab of the bar where another is (a drop): it takes its place, the others make room. */
export function placeTab(layout, barTabs, tabId, beforeId) {
  const ids = tabRows(layout, barTabs).map((row) => row.id)
  const from = ids.indexOf(tabId)
  const to = ids.indexOf(beforeId)
  if (from < 0 || to < 0 || from === to) return layout
  ids.splice(to, 0, ...ids.splice(from, 1))
  return withBarOrder(layout, barTabs, ids)
}

/** Hide a tab, or show it again. The Summary is never hidden: it is where the fields are. */
export function toggleTab(layout, tabId) {
  if (tabId === 'summary') return layout
  const hidden = list(layout?.hidden)
  return { ...layout, hidden: hidden.includes(tabId) ? hidden.filter((id) => id !== tabId) : [...hidden, tabId] }
}

/** An id for a new page, from its name: "Containment plan" → "containment-plan", made unique. */
export function newPageId(pages, name) {
  let base = String(name ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 24)
  if (!/^[a-z]/.test(base)) base = `page${base ? `-${base}` : ''}`
  const taken = new Set(list(pages).map((page) => page.id))
  let id = base
  for (let number = 2; taken.has(id); number += 1) id = `${base}-${number}`
  return id
}

/** Whether a type can still be given a page. */
export const canAddPage = (layout) => pagesOf(layout).length < PAGES_MAX

/** Add a page with that name and an empty grid: `{ layout, id }` (id null when it could not be added). */
export function addPage(layout, name) {
  const pages = pagesOf(layout)
  const cleaned = String(name ?? '')
    .trim()
    .slice(0, PAGE_NAME_MAX)
  if (!cleaned || pages.length >= PAGES_MAX) return { layout, id: null }
  const id = newPageId(pages, cleaned)
  return { layout: { ...layout, pages: [...pages, { id, name: cleaned, grid: [] }] }, id }
}

/** Rename a page: its tab is called by its name. */
export function renamePage(layout, pageId, name) {
  const text = String(name ?? '').slice(0, PAGE_NAME_MAX)
  return { ...layout, pages: pagesOf(layout).map((page) => (page.id === pageId ? { ...page, name: text } : page)) }
}

/** The grid of a page, replaced. */
export function setPageGrid(layout, pageId, grid) {
  return { ...layout, pages: pagesOf(layout).map((page) => (page.id === pageId ? { ...page, grid } : page)) }
}

/** Delete a page: it leaves the tabs with it. */
export function removePage(layout, pageId) {
  const tab = pageTabId(pageId)
  return {
    ...layout,
    pages: pagesOf(layout).filter((page) => page.id !== pageId),
    tabs: list(layout?.tabs).filter((id) => id !== tab),
    hidden: list(layout?.hidden).filter((id) => id !== tab),
  }
}

// --------------------------------------------------------------------------- //
// The close form                                                              //
// --------------------------------------------------------------------------- //

/** The sections the form of closing shows, in its order: those the layout still has. */
export function closeSections(layout) {
  const have = new Map(list(layout?.sections).map((section) => [section.id, section]))
  const seen = new Set()
  const out = []
  for (const id of list(layout?.close?.sections)) {
    if (!have.has(id) || seen.has(id)) continue
    seen.add(id)
    out.push(have.get(id))
  }
  return out
}

const withClose = (layout, ids) => {
  const { close: _close, ...rest } = layout ?? {}
  return ids.length > 0 ? { ...rest, close: { sections: ids } } : rest
}

/** Put a section in the close form (at its end), or take it out. */
export function toggleCloseSection(layout, sectionId) {
  const ids = closeSections(layout).map((section) => section.id)
  return withClose(layout, ids.includes(sectionId) ? ids.filter((id) => id !== sectionId) : [...ids, sectionId])
}

/** Move a section of the close form one place up or down. */
export function moveCloseSection(layout, sectionId, by) {
  const ids = closeSections(layout).map((section) => section.id)
  const from = ids.indexOf(sectionId)
  const to = from + by
  if (from < 0 || to < 0 || to >= ids.length) return layout
  ids.splice(to, 0, ...ids.splice(from, 1))
  return withClose(layout, ids)
}

/**
 * The fields the form of closing edits for a section: those of the registry
 * that can be written, in the order of the section. `flags` are the fields the
 * type lists (`{ name, requiredOnClose }`): `needed` says which must hold a value.
 */
export function closeFields(section, known, flags) {
  const wanted = new Set(
    list(flags)
      .filter((item) => item.requiredOnClose)
      .map((item) => item.name),
  )
  return list(section?.fields)
    .map((name) => known?.[name])
    .filter(
      (field) =>
        field &&
        field.writable !== false &&
        field.type !== 'timer' &&
        // What the form of closing asks itself, and what closing sets.
        !['type', 'status', 'close_reason', 'close_notes'].includes(field.name),
    )
    .map((field) => ({ field, needed: wanted.has(field.name) }))
}

/** "2 tasks of the work plan are still open." ('' when none is). */
export function openTasksText(count) {
  if (!count) return ''
  return count === 1 ? '1 task of the work plan is still open.' : `${count} tasks of the work plan are still open.`
}

// --------------------------------------------------------------------------- //
// The quick view                                                              //
// --------------------------------------------------------------------------- //
const quickKind = (id) => QUICK_KINDS.find((kind) => kind.id === id) ?? null

/**
 * The blocks of the quick view as the editor holds them: those the layout
 * keeps that can be drawn (a kind there is, a section the layout shows on its
 * page), a text kept even while it is empty, so that it can be typed.
 */
export function quickList(layout) {
  const sections = new Set(gridSections(layout).map((section) => section.id))
  const seen = new Set()
  const out = []
  for (const raw of list(layout?.quick).slice(0, QUICK_MAX)) {
    const kind = quickKind(raw?.kind)
    if (!kind) continue
    if (kind.id === 'section') {
      if (!sections.has(raw.section) || seen.has(`section:${raw.section}`)) continue
      seen.add(`section:${raw.section}`)
      out.push({ kind: 'section', section: raw.section })
    } else if (kind.id === 'note') {
      out.push({ kind: 'note', text: String(raw.text ?? '').slice(0, NOTE_MAX) })
    } else {
      if (seen.has(kind.id)) continue
      seen.add(kind.id)
      out.push({ kind: kind.id })
    }
  }
  return out
}

/** The sections no block of the quick view shows yet. */
export function quickFreeSections(layout) {
  const shown = new Set(
    quickList(layout)
      .filter((block) => block.kind === 'section')
      .map((block) => block.section),
  )
  return gridSections(layout).filter((section) => !shown.has(section.id))
}

/** Whether a block of a kind can still be added: there is room, and a kind that is there once is not there. */
export function canAddQuick(layout, kindId) {
  const kind = quickKind(kindId)
  const blocks = quickList(layout)
  if (!kind || blocks.length >= QUICK_MAX) return false
  if (kind.id === 'section') return quickFreeSections(layout).length > 0
  return !(kind.once && blocks.some((block) => block.kind === kind.id))
}

const withQuick = (layout, blocks) => {
  const { quick: _quick, ...rest } = layout ?? {}
  return blocks.length > 0 ? { ...rest, quick: blocks } : rest
}

/** Add a block at the end (a section block takes `sectionId`, or the first section that has none). */
export function addQuick(layout, kindId, sectionId = null) {
  if (!canAddQuick(layout, kindId)) return layout
  const block = { kind: kindId }
  if (kindId === 'section') block.section = sectionId ?? quickFreeSections(layout)[0].id
  if (kindId === 'note') block.text = ''
  return withQuick(layout, [...quickList(layout), block])
}

export function removeQuick(layout, index) {
  return withQuick(
    layout,
    quickList(layout).filter((_, at) => at !== index),
  )
}

export function moveQuick(layout, index, by) {
  const blocks = quickList(layout)
  const to = index + by
  if (index < 0 || index >= blocks.length || to < 0 || to >= blocks.length) return layout
  blocks.splice(to, 0, ...blocks.splice(index, 1))
  return withQuick(layout, blocks)
}

export function updateQuick(layout, index, changes) {
  return withQuick(
    layout,
    quickList(layout).map((block, at) => (at === index ? { ...block, ...changes } : block)),
  )
}

/** What the row "Quick view" of the editor says: "generated", or how many blocks. */
export function quickTag(layout) {
  const count = quickList(layout).length
  return count === 0 ? 'generated' : `${count} ${count === 1 ? 'block' : 'blocks'}`
}

/** What the row "Close form" of the editor says. */
export function closeTag(layout) {
  const count = closeSections(layout).length
  return count === 0 ? 'as it always was' : `${count} ${count === 1 ? 'section' : 'sections'}`
}

// --------------------------------------------------------------------------- //
// Saving                                                                      //
// --------------------------------------------------------------------------- //

/**
 * A layout as the server takes it: the grids cleaned, the pages named, and
 * nothing that names a section or a page that was taken away (the server
 * would refuse it): tabs of pages that are gone, sections of the close form,
 * blocks of the quick view. A text of the quick view left empty is dropped.
 */
export function layoutForSaving(layout) {
  if (!layout) return layout
  const { pages: _pages, close: _close, quick: _quick, ...rest } = layout
  const out = { ...rest }
  if (Array.isArray(layout.grid)) out.grid = cleanGrid(layout.grid, layout)
  const pages = pagesOf(layout)
  if (pages.length > 0) out.pages = pages.map((page) => ({ ...page, name: pageName(page) }))
  const known = new Set(pages.map((page) => pageTabId(page.id)))
  const real = (id) => pageIdOf(id) === null || known.has(id)
  if (Array.isArray(layout.tabs)) out.tabs = layout.tabs.filter(real)
  if (Array.isArray(layout.hidden)) out.hidden = layout.hidden.filter(real)
  const closing = closeSections(layout).map((section) => section.id)
  if (closing.length > 0) out.close = { sections: closing }
  const quick = quickList(layout).filter((block) => block.kind !== 'note' || block.text.trim())
  if (quick.length > 0) out.quick = quick
  return out
}
