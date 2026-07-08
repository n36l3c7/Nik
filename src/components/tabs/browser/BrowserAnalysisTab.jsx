import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  Bookmark,
  FolderInput,
  Info,
  Sparkles,
  Trash2,
  Upload,
  Zap,
} from 'lucide-react'
import { Button, Card, Modal } from '../../ui/index.js'
import FileUploadZone from './FileUploadZone.jsx'
import EventsSection from './EventsSection.jsx'
import BookmarksSection from './BookmarksSection.jsx'
import ShortcutsSection from './ShortcutsSection.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { parseBrowserSource } from '../../../services/fileParsers.js'
import { getDemoBrowserData } from '../../../services/demoData.js'
import {
  BROWSERS,
  getBrowserById,
  buildDefaultBrowserData,
  sourcePathFor,
} from '../../../config/browsers.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'

/*
 * "Browser Forensics" tab: one SUB-TAB per known browser (Chrome, Firefox,
 * Edge, Brave, Opera). Every browser exposes its own file sources (which differ
 * by engine: Chromium uses History/Bookmarks/Shortcuts, Firefox a single
 * places.sqlite), its own artifacts (history, downloads, bookmarks, shortcuts)
 * and the ability to clear its data per file or as a whole.
 */

/** Analysis sections available depending on the browser's artifacts. */
function sectionsFor(browser) {
  const sections = []
  if (browser.artifacts.includes('history') || browser.artifacts.includes('downloads')) {
    sections.push({ id: 'events', label: 'Events', icon: Activity })
  }
  if (browser.artifacts.includes('bookmarks')) {
    sections.push({ id: 'bookmarks', label: 'Bookmarks', icon: Bookmark })
  }
  if (browser.artifacts.includes('shortcuts')) {
    sections.push({ id: 'shortcuts', label: 'Shortcuts', icon: Zap })
  }
  return sections
}

/** Metadata of the file (source) that produces a given artifact. */
function sourceMetaFor(browser, browserData, artifact) {
  const source = browser.sources.find((s) => s.produces.includes(artifact))
  return source ? (browserData.meta?.[source.key] ?? null) : null
}

export default function BrowserAnalysisTab({ incident }) {
  const { updateBrowserData, setActiveBrowser, clearBrowserData, removeBrowserSource } =
    useIncidents()

  const [loading, setLoading] = useState({})
  const [errors, setErrors] = useState({})
  const [activeSection, setActiveSection] = useState('events')
  const [confirmClear, setConfirmClear] = useState(false)

  const browserData = incident.data.browser
  const activeBrowserId = getBrowserById(browserData.activeBrowser)
    ? browserData.activeBrowser
    : BROWSERS[0].id
  const browser = getBrowserById(activeBrowserId)

  // Host OS drives the artifact paths shown in the "where to find files" note.
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os

  // Data of the active browser (defensive fallback for partial incidents).
  const current = browserData.browsers[activeBrowserId] ?? buildDefaultBrowserData(browser)

  const sections = useMemo(() => sectionsFor(browser), [browser])

  // On browser/incident change: reset transient state and snap the active
  // section to one valid for the current browser.
  useEffect(() => {
    setErrors({})
    setLoading({})
    setActiveSection((prev) =>
      sections.some((s) => s.id === prev) ? prev : (sections[0]?.id ?? 'events'),
    )
  }, [activeBrowserId, incident.id, sections])

  // Counts per browser (sub-tab badge) and per section.
  const countForBrowser = (bd) =>
    (bd?.history?.length ?? 0) +
    (bd?.downloads?.length ?? 0) +
    (bd?.bookmarks?.length ?? 0) +
    (bd?.shortcuts?.length ?? 0)

  const sectionCount = {
    events: (current.history?.length ?? 0) + (current.downloads?.length ?? 0),
    bookmarks: current.bookmarks?.length ?? 0,
    shortcuts: current.shortcuts?.length ?? 0,
  }

  const hasData = countForBrowser(current) > 0

  // Sources not yet loaded (for the "where to find files" note).
  const missingSources = browser.sources.filter((s) => !current.meta?.[s.key])

  /* ---- Import a file for a source ---- */
  const handleFile = async (source, file) => {
    setErrors((prev) => ({ ...prev, [source.key]: null }))
    setLoading((prev) => ({ ...prev, [source.key]: true }))
    try {
      const { produced, format } = await parseBrowserSource(file, browser.engine, source)
      const rows = source.produces.reduce((sum, k) => sum + (produced[k]?.length ?? 0), 0)
      const patch = {
        meta: {
          ...current.meta,
          [source.key]: {
            fileName: file.name,
            format,
            rows,
            importedAt: new Date().toISOString(),
          },
        },
      }
      // A source owns all of its artifacts: it replaces (or clears) them.
      for (const key of source.produces) patch[key] = produced[key] ?? []
      updateBrowserData(incident.id, activeBrowserId, patch, {
        action: 'browser.upload',
        details: `Imported ${source.label} into ${activeBrowserId} (${rows} rows)`,
      })
    } catch (err) {
      setErrors((prev) => ({
        ...prev,
        [source.key]: err?.message ?? 'Unexpected error while parsing the file.',
      }))
    } finally {
      setLoading((prev) => ({ ...prev, [source.key]: false }))
    }
  }

  /* ---- Remove a single file ---- */
  const handleRemoveSource = (source) => {
    setErrors((prev) => ({ ...prev, [source.key]: null }))
    removeBrowserSource(incident.id, activeBrowserId, source.key, source.produces)
  }

  /* ---- Load demo data into the active browser ---- */
  const handleLoadDemo = () => {
    const demo = getDemoBrowserData(browser)
    const importedAt = new Date().toISOString()
    const patch = {
      history: demo.history ?? [],
      downloads: demo.downloads ?? [],
      bookmarks: demo.bookmarks ?? [],
      shortcuts: demo.shortcuts ?? [],
      meta: {},
    }
    // A "demo" metadata entry for each source of the browser.
    for (const source of browser.sources) {
      const rows = source.produces.reduce((sum, k) => sum + (demo[k]?.length ?? 0), 0)
      patch.meta[source.key] = {
        fileName: 'Demo data',
        format: 'demo',
        rows,
        importedAt,
      }
    }
    setErrors({})
    updateBrowserData(incident.id, activeBrowserId, patch, {
      action: 'browser.demo',
      details: `Loaded demo data into ${activeBrowserId}`,
    })
  }

  const handleConfirmClear = () => {
    clearBrowserData(incident.id, activeBrowserId)
    setErrors({})
    setConfirmClear(false)
  }

  return (
    <div className="space-y-6">
      {/* -------- Browser sub-tabs -------- */}
      <div
        role="tablist"
        aria-label="Browser"
        className="flex flex-wrap gap-2 rounded-xl border border-slate-200 bg-white p-2 dark:border-slate-800 dark:bg-slate-900"
      >
        {BROWSERS.map((b) => {
          const isActive = b.id === activeBrowserId
          const BrowserIcon = b.icon
          const count = countForBrowser(browserData.browsers[b.id])
          return (
            <button
              key={b.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveBrowser(incident.id, b.id)}
              className={[
                'inline-flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                isActive
                  ? 'border-cyan-500/60 bg-cyan-50 text-cyan-700 dark:border-cyan-500/50 dark:bg-cyan-500/10 dark:text-cyan-300'
                  : 'border-transparent text-slate-600 hover:bg-slate-50 dark:text-slate-400 dark:hover:bg-slate-800/60',
              ].join(' ')}
            >
              <BrowserIcon className={`h-4 w-4 ${isActive ? '' : b.accent}`} />
              {b.label}
              {count > 0 && (
                <span
                  className={[
                    'rounded-full px-1.5 text-xs tabular-nums',
                    isActive
                      ? 'bg-cyan-600/20 text-cyan-700 dark:text-cyan-300'
                      : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
                  ].join(' ')}
                >
                  {count.toLocaleString('en-US')}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* -------- "Where to find files" note (disappears once loaded) -------- */}
      {missingSources.length > 0 && (
        <div className="flex gap-3 rounded-xl border border-cyan-200 bg-cyan-50/60 p-4 text-sm dark:border-cyan-500/30 dark:bg-cyan-500/5">
          <FolderInput className="mt-0.5 h-5 w-5 shrink-0 text-cyan-600 dark:text-cyan-400" />
          <div className="min-w-0 space-y-1.5">
            <p className="font-medium text-slate-700 dark:text-slate-200">
              Where to find {browser.label} files ({osLabel})
            </p>
            <ul className="space-y-1">
              {missingSources.map((source) => (
                <li key={source.key} className="text-xs text-slate-600 dark:text-slate-400">
                  <span className="font-medium">{source.label}:</span>{' '}
                  <span className="break-all font-mono text-[11px] text-slate-500 dark:text-slate-400">
                    {sourcePathFor(source, os)}
                  </span>
                </li>
              ))}
            </ul>
            <p className="text-[11px] text-slate-400 dark:text-slate-500">
              Close the browser before copying the files (the databases may be
              locked). Each row disappears once the matching file is loaded.
            </p>
          </div>
        </div>
      )}

      {/* -------- Data sources card for the active browser -------- */}
      <Card
        title={`Data sources — ${browser.label}`}
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" icon={Sparkles} onClick={handleLoadDemo}>
              Load demo data
            </Button>
            {hasData && (
              <Button
                variant="danger"
                size="sm"
                icon={Trash2}
                onClick={() => setConfirmClear(true)}
              >
                Clear {browser.label}
              </Button>
            )}
          </div>
        }
      >
        <div
          className={[
            'grid gap-4',
            browser.sources.length === 1
              ? 'md:grid-cols-1'
              : browser.sources.length === 2
                ? 'md:grid-cols-2'
                : 'md:grid-cols-3',
          ].join(' ')}
        >
          {browser.sources.map((source) => (
            <FileUploadZone
              key={source.key}
              label={source.label}
              description={source.hint}
              icon={source.icon}
              accept={source.accept}
              pathHint={sourcePathFor(source, os)}
              meta={current.meta?.[source.key] ?? null}
              loading={!!loading[source.key]}
              error={errors[source.key] ?? null}
              onFile={(file) => handleFile(source, file)}
              onClear={() => handleRemoveSource(source)}
            />
          ))}
        </div>
      </Card>

      {/* -------- Sub-navigation for the active browser's sections -------- */}
      <nav aria-label="Browser analysis sections" className="flex flex-wrap gap-2">
        {sections.map((section) => {
          const isActive = activeSection === section.id
          const SectionIcon = section.icon
          return (
            <button
              key={section.id}
              type="button"
              aria-pressed={isActive}
              onClick={() => setActiveSection(section.id)}
              className={[
                'inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
                isActive
                  ? 'border-cyan-600 bg-cyan-600 text-white dark:border-cyan-500 dark:bg-cyan-600'
                  : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400 dark:hover:bg-slate-800/60',
              ].join(' ')}
            >
              <SectionIcon className="h-4 w-4" />
              {section.label}
              <span
                className={[
                  'rounded-full px-1.5 py-0.5 text-xs tabular-nums',
                  isActive
                    ? 'bg-white/20 text-white'
                    : 'bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400',
                ].join(' ')}
              >
                {(sectionCount[section.id] ?? 0).toLocaleString('en-US')}
              </span>
            </button>
          )
        })}
      </nav>

      {/* -------- Active section -------- */}
      {activeSection === 'events' && (
        <EventsSection
          incident={incident}
          browserId={activeBrowserId}
          history={current.history}
          downloads={current.downloads}
        />
      )}
      {activeSection === 'bookmarks' && (
        <BookmarksSection
          incident={incident}
          browserId={activeBrowserId}
          bookmarks={current.bookmarks}
          meta={sourceMetaFor(browser, current, 'bookmarks')}
        />
      )}
      {activeSection === 'shortcuts' && (
        <ShortcutsSection
          incident={incident}
          browserId={activeBrowserId}
          shortcuts={current.shortcuts}
          meta={sourceMetaFor(browser, current, 'shortcuts')}
        />
      )}

      {/* Informational note for Firefox (a single file for all artifacts) */}
      {browser.engine === 'firefox' && (
        <p className="flex items-center justify-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
          <Info className="h-3.5 w-3.5 shrink-0" />
          Firefox stores history, bookmarks and downloads in a single
          <span className="font-mono">places.sqlite</span> file.
        </p>
      )}

      {/* -------- Confirm "clear browser" modal -------- */}
      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title={`Clear ${browser.label} data`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} onClick={handleConfirmClear}>
              Clear {browser.label}
            </Button>
          </>
        }
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          You are about to delete all imported data for <strong>{browser.label}</strong>{' '}
          in the incident <strong>{incident.name}</strong> (history, downloads,
          bookmarks and shortcuts). Other browsers are left untouched. This action
          is irreversible.
        </p>
      </Modal>
    </div>
  )
}
