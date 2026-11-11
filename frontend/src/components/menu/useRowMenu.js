import { useCallback } from 'react'
import { Braces, Copy, Crosshair, ListTree, Search, ShieldCheck } from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useIocLookup } from '../../context/IocLookupContext.jsx'
import { useNavigation } from '../../context/NavigationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { defang, indicatorFlaggable } from '../../domain/iocs.js'
import { formatDateTime } from '../../lib/time.js'
import { flagItems } from './flagItems.js'

/*
 * ============================================================================
 * RIGHT-CLICK MENUS — the same sections, in the same order, everywhere
 * ============================================================================
 *
 * useItemMenu(incident) returns `menu(event, spec)`; a component calls it from
 * onContextMenu (or a DataTable's onRowContextMenu). `spec` says what the item
 * is, and the menu is built from the sections that apply:
 *
 *   actions    what the item itself offers (Open, Open as artifact, …)
 *   flaggable  flag / unflag and comment, when an incident is open: the
 *              payload the item's flag button passes to toggleFlag()
 *   ioc        { type, value }: where it was seen, search, copy, copy
 *              defanged, the allowlist; flaggable by hand when no
 *              `flaggable` is given
 *   text       "Copy as text"
 *   copy       [{ label, text }]: more things to copy (a hash, a path…)
 *   record     "Copy as JSON" (the row's own fields)
 *   timeline   "Show in the Timeline"
 *   danger     last, after a rule (Remove, Delete)
 *
 * Nothing to offer means no menu: the browser's own opens. useRowMenu() is the
 * shorthand of the event tables (flag, comment, copy, timeline).
 */

const INTERNAL = /^(_|soc$|kind$)/
// Hashes and paths are not defanged: nothing opens them by mistake.
const DEFANGABLE = new Set(['url', 'domain', 'ip', 'email'])

/** The row's own fields, without the UI's derived ones, for "Copy as JSON". */
function plain(record) {
  return Object.fromEntries(Object.entries(record ?? {}).filter(([key]) => !INTERNAL.test(key)))
}

async function writeClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function useItemMenu(incident) {
  const { openMenu, askText } = useContextMenu()
  const { toggleFlag, addFlagComment } = useIncidents()
  const { openIoc, openAllowlist } = useIocLookup()
  const { goTo, openSearch } = useNavigation()
  const { showToast } = useToast()

  return useCallback(
    (event, spec) => {
      const { actions = [], ioc = null, text = '', copy = [], record = null, timeline = false, danger = [] } = spec
      const canFlag = Boolean(incident?.id)
      const flaggable = spec.flaggable ?? (ioc ? indicatorFlaggable(ioc.type, ioc.value) : null)
      const notify = async (content, what) =>
        showToast({ message: (await writeClipboard(content)) ? `${what} copied.` : 'The browser refused to copy.' })

      const sections = [
        actions,
        canFlag && flaggable
          ? flagItems({
              incident,
              flaggable,
              toggleFlag,
              addFlagComment,
              askText,
              what: spec.flaggable ? (spec.what ?? '') : 'indicator',
            })
          : [],
        ioc
          ? [
              { label: 'Where else was this seen?', icon: Crosshair, onSelect: () => openIoc(ioc.type, ioc.value) },
              { label: 'Search for it', icon: Search, hint: 'ctrl k', onSelect: () => openSearch(String(ioc.value)) },
            ]
          : [],
        [
          text && { label: 'Copy as text', icon: Copy, onSelect: () => notify(text, 'Text') },
          ioc && { label: 'Copy', icon: Copy, onSelect: () => notify(String(ioc.value), 'Value') },
          ioc &&
            DEFANGABLE.has(ioc.type) && {
              label: 'Copy defanged',
              icon: Copy,
              hint: '[.]',
              onSelect: () => notify(defang(String(ioc.value)), 'Defanged value'),
            },
          ...copy
            .filter((item) => item?.text)
            .map((item) => ({
              label: `Copy ${item.label}`,
              icon: Copy,
              onSelect: () => notify(String(item.text), item.label[0].toUpperCase() + item.label.slice(1)),
            })),
          record && {
            label: 'Copy as JSON',
            icon: Braces,
            onSelect: () => notify(JSON.stringify(plain(record), null, 2), 'JSON'),
          },
        ],
        ioc
          ? [{ label: 'Add to the allowlist…', icon: ShieldCheck, onSelect: () => openAllowlist(ioc.type, ioc.value) }]
          : [],
        timeline && canFlag
          ? [
              {
                label: 'Show in the Timeline',
                icon: ListTree,
                onSelect: () =>
                  goTo('timeline', { search: spec.search ?? flaggable?.title ?? String(ioc?.value ?? '') }),
              },
            ]
          : [],
        danger,
      ]
        .map((section) => section.filter(Boolean))
        .filter((section) => section.length > 0)
      if (sections.length === 0) return false
      const items = sections.flatMap((section, index) => (index === 0 ? section : ['separator', ...section]))
      return openMenu(event, { title: spec.title ?? flaggable?.title ?? String(ioc?.value ?? ''), items })
    },
    [incident, openMenu, askText, toggleFlag, addFlagComment, openIoc, openAllowlist, goTo, openSearch, showToast],
  )
}

/**
 * The menu of an event row: flag, comment, copy as text or JSON, show in the
 * Timeline. Use:
 *   const rowMenu = useRowMenu(incident)
 *   <DataTable onRowContextMenu={(event, row) => rowMenu(event, { flaggable, record: row })} />
 */
export function useRowMenu(incident, { timeline = true } = {}) {
  const menu = useItemMenu(incident)
  return useCallback(
    (event, { flaggable, record }) => {
      if (!incident || !flaggable) return false
      const time = Number.isFinite(flaggable.time) ? formatDateTime(flaggable.time) : ''
      return menu(event, {
        title: flaggable.title || flaggable.url || 'Event',
        flaggable,
        text: [time, flaggable.title, flaggable.url].filter(Boolean).join('  '),
        record,
        timeline,
        search: flaggable.title || flaggable.url || '',
      })
    },
    [incident, menu, timeline],
  )
}
