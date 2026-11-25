import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Download, Eye, FolderInput, Globe, Info, Plus, ShieldAlert } from 'lucide-react'
import { Button, Modal, StatCard, Tabs, Wait, tabId } from '../../ui/index.js'
import SourceFiles from '../../evidence/SourceFiles.jsx'
import BrowserTable from './BrowserTable.jsx'
import DetectionsSection from '../../evidence/DetectionsSection.jsx'
import { useAuth } from '../../../context/AuthContext.jsx'
import { BROWSERS, getBrowserById, isBrowserAvailableOn, sourcePathFor } from '../../../config/browsers.js'
import { DEFAULT_OS, getOsById } from '../../../config/os.js'
import {
  DEFAULT_PROFILE,
  PROFILE_NAME_MAX,
  SECTIONS,
  browserItems,
  countText,
  expectedFor,
  hasRecords,
  inScope,
  matchFor,
  profileItems,
  profileNameError,
  profileNames,
  resolveProfileName,
  scopeFilters,
  scopedSources,
  sectionCount,
  domainStat,
  needsReread,
  sourceChoices,
  sourceForFile,
  typeTotals,
} from '../../../domain/browserEvidence.js'
import { noteEvidenceChanged } from '../../../lib/useEvidenceSummary.js'
import { detectionTone, levelsText } from '../../../domain/detections.js'
import { useDetections } from '../../../lib/useDetections.js'
import { evidence } from '../../../services/api.js'

/*
 * "Browser Forensics" (7.0): the browser and the profile are chosen with two rows of tabs, the files of
 * that profile are the SourceFiles table (the expected ones that are missing are grey rows), and what
 * the worker read of them is listed a page at a time by BrowserTable. Nothing is parsed in the browser.
 */

const ARCHIVED = 'Archived: the records are not loaded. Take the incident out of the archive to read them again.'

export default function BrowserAnalysisTab({ incident }) {
  const { can } = useAuth()
  const archived = Boolean(incident.archivedAt)
  const canWrite = can('write') && !archived

  const [sources, setSources] = useState(null)
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0) // bumped when a file changed: counts and tables are read again
  const [browserId, setBrowserId] = useState(BROWSERS[0].id)
  const [profile, setProfile] = useState(DEFAULT_PROFILE)
  const [added, setAdded] = useState({}) // browser id -> names of profiles added and not filled yet
  const [adding, setAdding] = useState(null) // the name being typed while the dialog is open
  const [section, setSection] = useState('events')
  const [asking, setAsking] = useState(null) // the file whose source the person is asked, and how it was answered
  const [picked, setPicked] = useState('')
  const askQueue = useRef(Promise.resolve()) // one question at a time when several files are added
  const [help, setHelp] = useState(false)
  const [stats, setStats] = useState(null)

  const browser = getBrowserById(browserId) ?? BROWSERS[0]
  const os = getOsById(incident.os) ? incident.os : DEFAULT_OS
  const osLabel = getOsById(os)?.label ?? os

  // ---- The files of every browser: the counts of the tabs, and what the table can read ----
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .sources(incident.id, { kind: 'browser', signal: controller.signal })
      .then(({ sources: list }) => {
        setSources(list)
        setError('')
      })
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setError(failure?.message || 'The files could not be listed.')
      })
    return () => controller.abort()
  }, [incident.id, version])

  const changed = useCallback(() => {
    setVersion((n) => n + 1)
    noteEvidenceChanged(incident.id)
  }, [incident.id])

  const list = useMemo(() => sources ?? [], [sources])
  const browsers = useMemo(() => browserItems(list), [list])
  const names = useMemo(() => profileNames(list, browserId, added[browserId]), [list, browserId, added])
  const profiles = useMemo(() => profileItems(list, browserId, added[browserId]), [list, browserId, added])
  const activeProfile = names.includes(profile) ? profile : names[0]
  const scoped = useMemo(() => scopedSources(list, browserId, activeProfile), [list, browserId, activeProfile])

  // The first load opens the first browser that has files.
  const [placed, setPlaced] = useState(false)
  useEffect(() => {
    if (placed || sources === null) return
    setPlaced(true)
    const first = browsers.find((item) => item.count > 0)
    if (first) setBrowserId(first.id)
  }, [placed, sources, browsers])

  const chooseBrowser = (id) => {
    setBrowserId(id)
    setProfile(DEFAULT_PROFILE)
  }
  const nameError = adding === null ? null : profileNameError(adding)
  const submitName = (event) => {
    event.preventDefault()
    if (nameError) return
    const name = resolveProfileName(names, adding)
    setAdded((held) => ({ ...held, [browserId]: [...new Set([...(held[browserId] ?? []), name])] }))
    setProfile(name)
    setAdding(null)
  }

  // ---- What the stat cards and the section counts say: the records the worker kept, by type ----
  const readable = useMemo(() => scoped.filter(hasRecords), [scoped])
  const readKey = readable.map((source) => `${source.id}:${source.state}:${source.kept}`).join('|')
  // The same scope for the tables, the stats and the stacks: the browser's sources and the profile, not a file.
  const scopeFor = useMemo(() => scopeFilters(browserId, activeProfile), [browserId, activeProfile])
  useEffect(() => {
    if (archived || readable.length === 0) {
      setStats(null)
      return undefined
    }
    const controller = new AbortController()
    const { signal } = controller
    const ask = (field, filters, limit) =>
      evidence.stack(incident.id, { field, order: 'common', limit, filters: { ...scopeFor, ...filters }, signal })
    Promise.all([ask('type', {}, 20), ask('data.domain', { type: 'visit' }, 1)])
      .then(([types, domains]) => setStats({ totals: typeTotals([types]), domains: domainStat(domains) }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setStats(null)
      })
    return () => controller.abort()
    // `readKey` stands for `readable`: the list is a new array at every read of the files.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident.id, archived, readKey, scopeFor, version])

  const totals = stats?.totals ?? {}
  // Detections is the last part: the rules that matched records of the browser section (all browsers).
  const found = useDetections(incident.id, {
    kind: 'browser',
    refresh: version,
    enabled: !archived && readable.length > 0,
  })
  const sectionItems = [
    ...SECTIONS.map((item) => ({ ...item, count: sectionCount(totals, item.id) })),
    { id: 'detections', label: 'Detections', count: found.data.total },
  ]
  const [focusRule, setFocusRule] = useState('') // a rule opened from Detections: Events shows only its records
  const [ruleTitles, setRuleTitles] = useState({}) // rule id -> title, for the chip of the filter

  // ---- Where the files come from ----
  const expected = useMemo(() => expectedFor(browser, os), [browser, os])
  const match = useMemo(() => matchFor(browserId), [browserId])
  const keep = useCallback((source) => inScope(source, browserId, activeProfile), [browserId, activeProfile])
  // A name the page cannot place is asked about, as the three cards of the old page did by being three.
  const uploadParams = useCallback(
    (file) => {
      const source = sourceForFile(browserId, file.name)
      if (source) return { source, profile: activeProfile }
      const question = () =>
        new Promise((resolve, reject) => {
          setPicked('')
          setAsking({
            file,
            choices: sourceChoices(browser),
            answer: (value) => resolve({ source: value, profile: activeProfile }),
            cancel: () => reject(Object.assign(new Error('The file was not sent.'), { name: 'AbortError' })),
          })
        })
      const turn = askQueue.current.then(question, question)
      askQueue.current = turn.then(
        () => undefined,
        () => undefined,
      )
      return turn
    },
    [browser, browserId, activeProfile],
  )
  const closeAsking = (value) => {
    if (value) asking.answer(value)
    else asking.cancel()
    setAsking(null)
  }
  const availableOnHost = isBrowserAvailableOn(browser, os)
  const pathsOsLabel = availableOnHost ? osLabel : browser.platforms.map((id) => getOsById(id)?.label ?? id).join(' / ')

  return (
    <div className="space-y-6">
      <Tabs
        variant="selector"
        label="Browser"
        idPrefix="browser"
        items={browsers}
        value={browserId}
        onChange={chooseBrowser}
      />
      <div className="flex flex-wrap items-center gap-3">
        <Tabs
          variant="selector"
          label={`${browser.label} profiles`}
          idPrefix="browser-profile"
          items={profiles}
          value={activeProfile}
          onChange={setProfile}
        />
        {canWrite && (
          <Button variant="secondary" size="sm" icon={Plus} onClick={() => setAdding('')}>
            Add profile
          </Button>
        )}
      </div>

      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-4 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
      {archived && (
        <p role="status" className="border border-line bg-panel px-4 py-2 text-sm text-fg-muted">
          {ARCHIVED}
        </p>
      )}

      <SourceFiles
        incidentId={incident.id}
        kind="browser"
        title={`Sources — ${browser.label} · ${activeProfile}`}
        filter={keep}
        uploadParams={uploadParams}
        expected={expected}
        match={match}
        canWrite={canWrite}
        onChanged={changed}
        help={
          <Button variant="ghost" size="sm" icon={FolderInput} onClick={() => setHelp(true)}>
            Where to find these files
          </Button>
        }
      />

      {!archived && readable.length > 0 && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard icon={Eye} label="Total visits" value={stats ? countText(totals.visit ?? 0) : '…'} />
            <StatCard
              icon={Globe}
              label="Unique domains"
              value={stats ? countText(stats.domains.count, stats.domains.capped) : '…'}
              hint={needsReread(scoped) ? 'Read the file again to count its domains' : undefined}
            />
            <StatCard
              icon={Download}
              label="Downloads"
              value={stats ? countText(totals.download ?? 0) : '…'}
              tone={totals.download > 0 ? 'accent' : 'default'}
            />
            <StatCard
              icon={ShieldAlert}
              label="Detections"
              value={found.data.detections.toLocaleString('en-US')}
              tone={detectionTone(found.data.byLevel)}
              hint={levelsText(found.data.byLevel) || undefined}
            />
          </div>

          <Tabs
            variant="section"
            label="Browser records"
            idPrefix="browser-section"
            items={sectionItems}
            value={section}
            onChange={(id) => {
              setFocusRule('')
              setSection(id)
            }}
          />
          <div role="tabpanel" aria-labelledby={tabId('browser-section', section)}>
            {section === 'detections' ? (
              <DetectionsSection
                data={found.data}
                loading={found.loading}
                error={found.error}
                noun="records"
                onOpen={(rule) => {
                  setRuleTitles((before) => ({ ...before, [rule.ruleId]: rule.title }))
                  setFocusRule(rule.ruleId)
                  setSection('events')
                }}
              />
            ) : (
              <BrowserTable
                key={`${incident.id}|${browserId}|${activeProfile}|${section}|${focusRule}`}
                incident={incident}
                section={section}
                scope={scopeFor}
                sources={list}
                canWrite={canWrite}
                focusRule={focusRule}
                ruleTitles={ruleTitles}
              />
            )}
          </div>
        </>
      )}
      {!archived && sources === null && !error && <Wait>Loading the files…</Wait>}

      {browser.engine === 'firefox' && (
        <p className="flex items-center justify-center gap-1.5 text-xs text-fg-muted">
          <Info className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
          Firefox stores history, bookmarks and downloads in a single <span className="font-mono">
            places.sqlite
          </span>{' '}
          file.
        </p>
      )}

      {/* -------- Where to find the files (kept from the old page) -------- */}
      <Modal
        open={help}
        onClose={() => setHelp(false)}
        title={`Where to find ${browser.label} files (${pathsOsLabel})`}
        maxWidth="max-w-2xl"
        footer={
          <Button variant="secondary" onClick={() => setHelp(false)}>
            Close
          </Button>
        }
      >
        <div className="space-y-2 text-sm">
          {!availableOnHost && (
            <p className="text-xs text-med">
              {browser.label} exists only on {pathsOsLabel}, but this incident&apos;s host runs {osLabel}: these files
              must come from a {pathsOsLabel} host.
            </p>
          )}
          <ul className="space-y-1">
            {browser.sources.map((source) => (
              <li key={source.key} className="text-xs text-fg-muted">
                <span className="font-medium">{source.label}:</span>{' '}
                <span className="break-all font-mono text-[11px]">{sourcePathFor(source, os)}</span>
              </li>
            ))}
          </ul>
          {browser.profileHint && (
            <p className="text-xs text-fg-muted">
              <span className="font-mono">&lt;profile&gt;</span> is the profile folder: {browser.profileHint}.
            </p>
          )}
          <p className="text-[11px] text-fg-muted">
            Close the browser before copying the files (the databases may be locked). Each grey row disappears once the
            matching file is added.
          </p>
        </div>
      </Modal>

      {/* -------- Which file it is, when its name does not say -------- */}
      <Modal
        open={asking !== null}
        onClose={() => closeAsking('')}
        title="Which file is it?"
        footer={
          <>
            <Button variant="secondary" onClick={() => closeAsking('')}>
              Cancel
            </Button>
            <Button type="submit" form="form-browser-source" disabled={!picked}>
              Add the file
            </Button>
          </>
        }
      >
        <form
          id="form-browser-source"
          onSubmit={(event) => {
            event.preventDefault()
            if (picked) closeAsking(picked)
          }}
        >
          <fieldset className="space-y-2">
            <legend className="mb-2 text-sm text-fg">
              <span className="break-all font-mono">{asking?.file.name}</span> is not a name of {browser.label}: which
              of its files is it?
            </legend>
            {(asking?.choices ?? []).map((choice) => (
              <label key={choice.value} className="flex items-center gap-2 text-sm text-fg">
                <input
                  type="radio"
                  name="browser-source"
                  value={choice.value}
                  checked={picked === choice.value}
                  onChange={() => setPicked(choice.value)}
                  className="accent-accent"
                />
                {choice.label}
              </label>
            ))}
          </fieldset>
        </form>
      </Modal>

      {/* -------- A new profile: the name files are added under -------- */}
      <Modal
        open={adding !== null}
        onClose={() => setAdding(null)}
        title={`New ${browser.label} profile`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setAdding(null)}>
              Cancel
            </Button>
            <Button type="submit" form="form-browser-profile" disabled={Boolean(nameError)}>
              Add profile
            </Button>
          </>
        }
      >
        <form id="form-browser-profile" onSubmit={submitName} className="space-y-2">
          <label htmlFor="browser-profile-name" className="block text-sm font-medium text-fg">
            Profile name
          </label>
          <input
            id="browser-profile-name"
            type="text"
            value={adding ?? ''}
            onChange={(event) => setAdding(event.target.value)}
            placeholder={browser.profileHint ? 'e.g. Profile 1' : 'e.g. Work'}
            maxLength={PROFILE_NAME_MAX}
            autoFocus
            aria-invalid={Boolean(nameError) && Boolean(adding)}
            className="w-full border border-line bg-panel px-3 py-2 text-sm text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          {nameError && adding && <p className="text-xs text-high">{nameError}</p>}
          <p className="text-xs text-fg-muted">
            The profile exists once a file is added to it.
            {browser.profileHint ? ` Tip: use the name of the profile folder (${browser.profileHint}).` : ''}
          </p>
        </form>
      </Modal>
    </div>
  )
}
