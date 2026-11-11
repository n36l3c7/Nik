import { useEffect, useMemo, useState } from 'react'
import { Activity, Bookmark, FolderInput, Info, Trash2, Upload, Zap } from 'lucide-react'
import { Button, Card, Modal } from '../../ui/index.js'
import FileUploadZone from './FileUploadZone.jsx'
import EventsSection from './EventsSection.jsx'
import BookmarksSection from './BookmarksSection.jsx'
import ShortcutsSection from './ShortcutsSection.jsx'
import ProfileBar from './ProfileBar.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { parseBrowserSource } from '../../../parsers/fileParsers.js'
import { sha256Hex } from '../../../lib/hash.js'
import {
  BROWSERS,
  getBrowserById,
  buildDefaultBrowserData,
  sourcePathFor,
  isBrowserAvailableOn,
} from '../../../config/browsers.js'
import { getOsById, DEFAULT_OS } from '../../../config/os.js'
import { activeProfileOf, browserRowCount, profileRowCount } from '../../../domain/browserProfiles.js'

/*
 * "Browser Forensics" tab: one SUB-TAB per known browser (Chrome, Firefox,
 * Edge, Brave, Opera, Safari). Every browser exposes its own file sources
 * (which differ by engine: Chromium uses History/Bookmarks/Shortcuts, Firefox a
 * single places.sqlite, Safari History.db plus two plists), its own PROFILES
 * (Default, Profile 1, … — each with its own files and data), its own artifacts (history, downloads, bookmarks, shortcuts)
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
function sourceMetaFor(browser, profileData, artifact) {
  const source = browser.sources.find((s) => s.produces.includes(artifact))
  return source ? (profileData.meta?.[source.key] ?? null) : null
}

export default function BrowserAnalysisTab({ incident }) {
  const {
    updateBrowserData,
    setActiveBrowser,
    setActiveProfile,
    addBrowserProfile,
    renameBrowserProfile,
    deleteBrowserProfile,
    clearBrowserData,
    removeBrowserSource,
  } = useIncidents()

  const [loading, setLoading] = useState({})
  const [errors, setErrors] = useState({})
  const [activeSection, setActiveSection] = useState('events')
  const [confirmClear, setConfirmClear] = useState(false)

  const browserData = incident.data.browser
  const activeBrowserId = getBrowserById(browserData.activeBrowser) ? browserData.activeBrowser : BROWSERS[0].id
  const browser = getBrowserById(activeBrowserId)

  // Host OS drives the artifact paths shown in the "where to find files" note.
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os
  // A macOS-only browser (Safari) on a Windows/Linux incident: the paths shown
  // are those of the platforms it exists on, with a warning.
  const availableOnHost = isBrowserAvailableOn(browser, os)
  const pathsOsLabel = availableOnHost ? osLabel : browser.platforms.map((id) => getOsById(id)?.label ?? id).join(' / ')

  // Active browser (defensive fallback for partial incidents) and its active
  // profile: every upload, section and count below refers to that profile.
  const slot = browserData.browsers[activeBrowserId] ?? buildDefaultBrowserData(browser)
  const current = activeProfileOf(slot)
  const profileId = current.id

  const sections = useMemo(() => sectionsFor(browser), [browser])

  // On browser/incident change: reset transient state and snap the active
  // section to one valid for the current browser.
  useEffect(() => {
    setErrors({})
    setLoading({})
    setActiveSection((prev) => (sections.some((s) => s.id === prev) ? prev : (sections[0]?.id ?? 'events')))
  }, [activeBrowserId, profileId, incident.id, sections])

  // Counts per browser (sub-tab badge, all profiles) and per section (active profile).

  const sectionCount = {
    events: (current.history?.length ?? 0) + (current.downloads?.length ?? 0),
    bookmarks: current.bookmarks?.length ?? 0,
    shortcuts: current.shortcuts?.length ?? 0,
  }

  const hasData = profileRowCount(current) > 0

  // Sources not yet loaded (for the "where to find files" note).
  const missingSources = browser.sources.filter((s) => !current.meta?.[s.key])

  /* ---- Import a file for a source ---- */
  const handleFile = async (source, file) => {
    setErrors((prev) => ({ ...prev, [source.key]: null }))
    setLoading((prev) => ({ ...prev, [source.key]: true }))
    try {
      const [{ produced, format }, sha256] = await Promise.all([
        parseBrowserSource(file, browser.engine, source),
        sha256Hex(file),
      ])
      const rows = source.produces.reduce((sum, k) => sum + (produced[k]?.length ?? 0), 0)
      const patch = {
        meta: {
          [source.key]: {
            fileName: file.name,
            format,
            rows,
            importedAt: new Date().toISOString(),
            sha256,
          },
        },
      }
      // A source owns all of its artifacts: it replaces (or clears) them.
      for (const key of source.produces) patch[key] = produced[key] ?? []
      updateBrowserData(incident.id, activeBrowserId, profileId, patch)
    } catch (err) {
      setErrors((prev) => ({
        ...prev,
        [source.key]: err?.message ?? 'Unexpected error while parsing the file.',
      }))
    } finally {
      setLoading((prev) => ({ ...prev, [source.key]: false }))
    }
  }

  // A file dropped anywhere in the app for this tab (see NavigationContext):
  // switch to its browser first, then import it into the active profile.
  const { requests, take } = useNavigation()
  useEffect(() => {
    const request = requests.browser
    if (!request?.file) return
    if (request.params?.browser && request.params.browser !== activeBrowserId) {
      setActiveBrowser(incident.id, request.params.browser)
      return
    }
    take('browser')
    const source = browser.sources.find((s) => s.key === request.params?.source) ?? browser.sources[0]
    handleFile(source, request.file)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [requests.browser, activeBrowserId])

  /* ---- Remove a single file ---- */
  const handleRemoveSource = (source) => {
    setErrors((prev) => ({ ...prev, [source.key]: null }))
    removeBrowserSource(incident.id, activeBrowserId, profileId, source.key, source.produces)
  }

  const handleConfirmClear = () => {
    clearBrowserData(incident.id, activeBrowserId, profileId)
    setErrors({})
    setConfirmClear(false)
  }

  return (
    <div className="space-y-6">
      {/* -------- Browser sub-tabs -------- */}
      <div role="tablist" aria-label="Browser" className="flex flex-wrap gap-2 border border-line bg-panel p-2">
        {BROWSERS.map((b) => {
          const isActive = b.id === activeBrowserId
          const BrowserIcon = b.icon
          const count = browserRowCount(browserData.browsers[b.id])
          return (
            <button
              key={b.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveBrowser(incident.id, b.id)}
              className={[
                'inline-flex items-center gap-2 border px-3 py-2 text-sm font-medium transition-colors',
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                isActive
                  ? 'border-accent-strong bg-accent-soft text-accent'
                  : 'border-transparent text-fg-muted hover:bg-canvas',
              ].join(' ')}
            >
              <BrowserIcon className={`h-4 w-4 ${isActive ? '' : b.accent}`} />
              {b.label}
              {count > 0 && (
                <span
                  className={[
                    'rounded-full px-1.5 text-xs tabular-nums',
                    isActive ? 'bg-accent-soft text-accent' : 'bg-canvas text-fg-muted',
                  ].join(' ')}
                >
                  {count.toLocaleString('en-US')}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* -------- Profiles of the active browser -------- */}
      <ProfileBar
        browser={browser}
        slot={slot}
        activeProfileId={profileId}
        onSelect={(id) => setActiveProfile(incident.id, activeBrowserId, id)}
        onAdd={(name) => addBrowserProfile(incident.id, activeBrowserId, name)}
        onRename={(id, name) => renameBrowserProfile(incident.id, activeBrowserId, id, name)}
        onDelete={(id) => deleteBrowserProfile(incident.id, activeBrowserId, id)}
      />

      {/* -------- "Where to find files" note (disappears once loaded) -------- */}
      {missingSources.length > 0 && (
        <div className="flex gap-3 border border-accent-strong bg-accent-soft p-4 text-sm">
          <FolderInput className="mt-0.5 h-5 w-5 shrink-0 text-accent" />
          <div className="min-w-0 space-y-1.5">
            <p className="font-medium text-fg">
              Where to find {browser.label} files ({pathsOsLabel})
            </p>
            {!availableOnHost && (
              <p className="text-xs text-med">
                {browser.label} exists only on {pathsOsLabel}, but this incident&apos;s host runs {osLabel}: these files
                must come from a {pathsOsLabel} host.
              </p>
            )}
            <ul className="space-y-1">
              {missingSources.map((source) => (
                <li key={source.key} className="text-xs text-fg-muted">
                  <span className="font-medium">{source.label}:</span>{' '}
                  <span className="break-all font-mono text-[11px] text-fg-muted">{sourcePathFor(source, os)}</span>
                </li>
              ))}
            </ul>
            {browser.profileHint && (
              <p className="text-xs text-fg-muted">
                <span className="font-mono">&lt;profile&gt;</span> is the profile folder: {browser.profileHint}.
              </p>
            )}
            <p className="text-[11px] text-fg-muted">
              Close the browser before copying the files (the databases may be locked). Each row disappears once the
              matching file is loaded.
            </p>
          </div>
        </div>
      )}

      {/* -------- Data sources card for the active browser -------- */}
      <Card
        title={`Data sources — ${browser.label} · ${current.name}`}
        icon={Upload}
        actions={
          <div className="flex items-center gap-2">
            {hasData && (
              <Button variant="danger" size="sm" icon={Trash2} onClick={() => setConfirmClear(true)}>
                Clear profile
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
                'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                isActive
                  ? 'border-accent-strong bg-accent text-white'
                  : 'border-line bg-panel text-fg-muted hover:bg-canvas',
              ].join(' ')}
            >
              <SectionIcon className="h-4 w-4" />
              {section.label}
              <span
                className={[
                  'rounded-full px-1.5 py-0.5 text-xs tabular-nums',
                  isActive ? 'bg-panel/20 text-white' : 'bg-canvas text-fg-muted',
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
          profile={current}
          history={current.history}
          downloads={current.downloads}
        />
      )}
      {activeSection === 'bookmarks' && (
        <BookmarksSection
          incident={incident}
          browserId={activeBrowserId}
          profile={current}
          bookmarks={current.bookmarks}
          meta={sourceMetaFor(browser, current, 'bookmarks')}
        />
      )}
      {activeSection === 'shortcuts' && (
        <ShortcutsSection
          incident={incident}
          browserId={activeBrowserId}
          profile={current}
          shortcuts={current.shortcuts}
          meta={sourceMetaFor(browser, current, 'shortcuts')}
        />
      )}

      {/* Informational note for Firefox (a single file for all artifacts) */}
      {browser.engine === 'firefox' && (
        <p className="flex items-center justify-center gap-1.5 text-xs text-fg-muted">
          <Info className="h-3.5 w-3.5 shrink-0" />
          Firefox stores history, bookmarks and downloads in a single
          <span className="font-mono">places.sqlite</span> file.
        </p>
      )}

      {/* -------- Confirm "clear profile" modal -------- */}
      <Modal
        open={confirmClear}
        onClose={() => setConfirmClear(false)}
        title={`Clear ${browser.label} · ${current.name} data`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmClear(false)}>
              Cancel
            </Button>
            <Button variant="danger" icon={Trash2} onClick={handleConfirmClear}>
              Clear profile
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg-muted">
          You are about to delete all imported data of the <strong>{browser.label}</strong> profile{' '}
          <strong>{current.name}</strong> in the incident <strong>{incident.name}</strong> (history, downloads,
          bookmarks and shortcuts). The profile itself, other profiles and other browsers are left untouched. This
          action is irreversible.
        </p>
      </Modal>
    </div>
  )
}
