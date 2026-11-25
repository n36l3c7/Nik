import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { DEFAULT_MALWARE_KEYWORDS, DEFAULT_BUSINESS_HOURS } from '../config/detectionRules.js'
import { api } from '../services/api.js'
import { createSocEngine } from '../domain/soc.js'
import { useAuth } from './AuthContext.jsx'

/*
 * ============================================================================
 * PLATFORM SETTINGS (global, shared by all analysts) — backed by the API
 * ============================================================================
 *
 *  - businessHours: { startHour, endHour, flagWeekends, tz }: business hours, told in the zone `tz`; the
 *                   server's rules and timers use them, and events OUTSIDE this window are marked as a
 *                   time anomaly.
 *  - iocAllowlist:  indicators hidden by default in the IOCs tab and left out
 *                   of exports (domains, IPs/CIDRs, exact values). null until
 *                   the server answers, so a PUT never overwrites the stored
 *                   list with an empty one (the server keeps it on null).
 *  - report:        { orgName, logo } printed on incident reports (logo: a
 *                   data: URI); null until loaded, for the same reason.
 *  - mail:          { orgDomains, trustedAuthServers } for Mail Analysis
 *                   (your own domains; servers whose Authentication-Results
 *                   can be believed); null until loaded.
 *  - enrichment:    { auto: { ip, url, hash }, retentionDays: { ip, url, hash }, refreshExpired }
 *                   threat-intelligence lookups (which sources are asked is not a
 *                   setting: a source is on when an instance of its connector is);
 *                   null until loaded.
 *
 * The factory defaults live in config/detectionRules.js. On mount the provider
 * starts from those defaults; once authenticated it loads the shared settings
 * from GET /settings and, from then on, every mutation is mirrored to the
 * server via PUT /settings (optimistic — local state updates immediately and a
 * momentary server hiccup never blocks editing).
 */

const SettingsContext = createContext(null)

// Threat intelligence as the server fills it in when nothing was saved.
const DEFAULT_ENRICHMENT = {
  auto: { ip: false, url: false, hash: false },
  retentionDays: { ip: 30, url: 30, hash: 180 },
  refreshExpired: true,
}

/** Factory-default settings (used before the server responds). */
function factorySettings() {
  return {
    businessHours: { ...DEFAULT_BUSINESS_HOURS },
    iocAllowlist: null,
    iocAllowlistDefault: [],
    report: null,
    mail: null,
    enrichment: null,
  }
}

// The keys PUT /api/settings takes: one left out keeps what the server has.
const SENT_KEYS = ['businessHours', 'iocAllowlist', 'report', 'mail', 'enrichment']

/** Normalize a settings document coming from the server. */
function normalizeSettings(doc) {
  return {
    businessHours: { ...DEFAULT_BUSINESS_HOURS, ...(doc?.businessHours ?? {}) },
    iocAllowlist: Array.isArray(doc?.iocAllowlist) ? doc.iocAllowlist : null,
    iocAllowlistDefault: Array.isArray(doc?.iocAllowlistDefault) ? doc.iocAllowlistDefault : [],
    report: doc?.report && typeof doc.report === 'object' ? { orgName: '', logo: '', ...doc.report } : null,
    mail:
      doc?.mail && typeof doc.mail === 'object'
        ? { orgDomains: doc.mail.orgDomains ?? [], trustedAuthServers: doc.mail.trustedAuthServers ?? [] }
        : null,
    enrichment:
      doc?.enrichment && typeof doc.enrichment === 'object'
        ? {
            auto: { ip: false, url: false, hash: false, ...(doc.enrichment.auto ?? {}) },
            retentionDays: { ...DEFAULT_ENRICHMENT.retentionDays, ...(doc.enrichment.retentionDays ?? {}) },
            refreshExpired: doc.enrichment.refreshExpired ?? true,
          }
        : null,
  }
}

export function SettingsProvider({ children }) {
  const { isAuthenticated } = useAuth()
  const [settings, setSettings] = useState(factorySettings)

  // Gate server writes: only persist once we have synced with the server (or
  // decided to proceed offline). Prevents clobbering the shared settings with
  // the factory defaults during the initial render, before GET /settings.
  const canPersist = useRef(false)
  // What the server is known to hold: only the keys that differ from it are sent, so a list
  // changed elsewhere (Settings → Lists, a playbook) is not written over with what this page read.
  const synced = useRef(null)

  // Load the shared settings whenever the user becomes authenticated.
  useEffect(() => {
    if (!isAuthenticated) {
      canPersist.current = false
      return
    }
    let cancelled = false
    api
      .get('/settings')
      .then((doc) => {
        if (cancelled) return
        const next = normalizeSettings(doc)
        synced.current = next
        setSettings(next)
      })
      .catch(() => {
        /* keep whatever is in state (factory defaults or prior values) */
      })
      .finally(() => {
        if (!cancelled) canPersist.current = true
      })
    return () => {
      cancelled = true
    }
  }, [isAuthenticated])

  // Mirror every change to the server (optimistic, fire-and-forget).
  useEffect(() => {
    if (!canPersist.current) return
    const before = synced.current ?? {}
    const changed = Object.fromEntries(
      SENT_KEYS.filter((key) => JSON.stringify(settings[key]) !== JSON.stringify(before[key])).map((key) => [
        key,
        settings[key],
      ]),
    )
    if (Object.keys(changed).length === 0) return
    synced.current = settings
    api.put('/settings', changed).catch(() => {
      /* optimistic: local state is the source of truth for this session */
    })
  }, [settings])

  /** Read the settings again: a list they are filled from was changed elsewhere. */
  const reload = useCallback(async () => {
    try {
      const next = normalizeSettings(await api.get('/settings'))
      synced.current = next
      setSettings(next)
    } catch {
      /* what is in state stays */
    }
  }, [])

  /** Updates the business hours (partial merge). */
  const setBusinessHours = useCallback((patch) => {
    setSettings((prev) => ({ ...prev, businessHours: { ...prev.businessHours, ...patch } }))
  }, [])

  /** Replaces the IOC allowlist (one entry per item; blanks dropped). */
  const setIocAllowlist = useCallback((entries) => {
    setSettings((prev) => ({ ...prev, iocAllowlist: entries.map((e) => e.trim()).filter(Boolean) }))
  }, [])

  /** Updates the report header (organisation name and/or logo). */
  const setReportBranding = useCallback((patch) => {
    setSettings((prev) => ({ ...prev, report: { orgName: '', logo: '', ...(prev.report ?? {}), ...patch } }))
  }, [])

  /** Replaces the Mail Analysis settings (own domains, trusted servers). */
  const setMailSettings = useCallback((patch) => {
    const clean = (list) => [
      ...new Set((list ?? []).map((d) => d.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean)),
    ]
    setSettings((prev) => {
      const next = { orgDomains: [], trustedAuthServers: [], ...(prev.mail ?? {}), ...patch }
      return {
        ...prev,
        mail: { orgDomains: clean(next.orgDomains), trustedAuthServers: clean(next.trustedAuthServers) },
      }
    })
  }, [])

  /** Updates the threat-intelligence settings (partial merge). */
  const setEnrichment = useCallback((patch) => {
    setSettings((prev) => {
      const current = prev.enrichment ?? structuredClone(DEFAULT_ENRICHMENT)
      return {
        ...prev,
        enrichment: {
          ...current,
          ...patch,
          auto: { ...current.auto, ...(patch.auto ?? {}) },
          retentionDays: { ...current.retentionDays, ...(patch.retentionDays ?? {}) },
        },
      }
    })
  }, [])

  const value = useMemo(
    () => ({
      businessHours: settings.businessHours,
      iocAllowlist: settings.iocAllowlist,
      iocAllowlistDefault: settings.iocAllowlistDefault,
      reportBranding: settings.report,
      mailSettings: settings.mail,
      enrichmentSettings: settings.enrichment,
      setBusinessHours,
      setIocAllowlist,
      setReportBranding,
      setMailSettings,
      setEnrichment,
      reload,
    }),
    [settings, setBusinessHours, setIocAllowlist, setReportBranding, setMailSettings, setEnrichment, reload],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

/** Hook to access the platform settings. */
export function useSettings() {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within <SettingsProvider>')
  return ctx
}

/**
 * Hook that provides a memoized engine for what is still analysed in the browser (the keywords of the
 * Malware tab, and the business hours for the events of the other tabs), rebuilt when the hours change.
 * Host evidence is not here: its rules are Sigma rules, run by the server.
 */
export function useSocEngine() {
  const { businessHours } = useSettings()
  return useMemo(() => createSocEngine({ malwareKeywords: DEFAULT_MALWARE_KEYWORDS, businessHours }), [businessHours])
}
