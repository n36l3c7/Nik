import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import {
  DEFAULT_SUSPICIOUS_KEYWORDS,
  DEFAULT_COMMAND_KEYWORDS,
  DEFAULT_ARTIFACT_KEYWORDS,
  DEFAULT_MALWARE_KEYWORDS,
  DEFAULT_BUSINESS_HOURS,
} from '../config/detectionRules.js'
import { api } from '../services/api.js'
import { createSocEngine } from '../domain/soc.js'
import { useAuth } from './AuthContext.jsx'

/*
 * ============================================================================
 * PLATFORM SETTINGS (global, shared by all analysts) — backed by the API
 * ============================================================================
 *
 *  - keywords:      SOC detection rules editable by the user
 *                   (add / edit / remove; severity 'high' or 'medium')
 *  - businessHours: business hours; events OUTSIDE this window are marked as a
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
 *  - enrichment:    { auto: { ip, url, hash }, ttlHours, providers: { id: bool } }
 *                   threat-intelligence lookups (the API keys never come here);
 *                   null until loaded.
 *
 * The factory defaults live in config/detectionRules.js. On mount the provider
 * starts from those defaults; once authenticated it loads the shared settings
 * from GET /settings and, from then on, every mutation is mirrored to the
 * server via PUT /settings (optimistic — local state updates immediately and a
 * momentary server hiccup never blocks editing).
 */

const SettingsContext = createContext(null)

/** Generates a unique id for keyword rules created by the user. */
function newId() {
  return crypto.randomUUID?.() ?? `kw-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

/** True if `pattern` is a valid RegExp (used by the UI to validate input). */
export function isValidRegex(pattern) {
  try {
    new RegExp(pattern, 'i')
    return true
  } catch {
    return false
  }
}

/** Factory-default settings (used before the server responds). */
function factorySettings() {
  return {
    keywords: structuredClone(DEFAULT_SUSPICIOUS_KEYWORDS),
    businessHours: { ...DEFAULT_BUSINESS_HOURS },
    iocAllowlist: null,
    iocAllowlistDefault: [],
    report: null,
    mail: null,
    enrichment: null,
  }
}

/** Normalize a settings document coming from the server. */
function normalizeSettings(doc) {
  return {
    keywords: Array.isArray(doc?.keywords) ? doc.keywords : structuredClone(DEFAULT_SUSPICIOUS_KEYWORDS),
    businessHours: {
      ...DEFAULT_BUSINESS_HOURS,
      ...(doc?.businessHours ?? {}),
    },
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
            ttlHours: doc.enrichment.ttlHours ?? 24,
            providers: { ...(doc.enrichment.providers ?? {}) },
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
        setSettings(normalizeSettings(doc))
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
    api.put('/settings', settings).catch(() => {
      /* optimistic: local state is the source of truth for this session */
    })
  }, [settings])

  /** Adds a new keyword rule (id generated if missing). */
  const addKeyword = useCallback((rule) => {
    const clean = {
      id: rule.id || newId(),
      label: rule.label?.trim() || rule.pattern,
      pattern: rule.pattern,
      severity: rule.severity === 'high' ? 'high' : 'medium',
      description: rule.description?.trim() || '',
    }
    setSettings((prev) => ({ ...prev, keywords: [...prev.keywords, clean] }))
    return clean
  }, [])

  /** Edits an existing rule (partial merge). */
  const updateKeyword = useCallback((id, patch) => {
    setSettings((prev) => ({
      ...prev,
      keywords: prev.keywords.map((k) =>
        k.id === id
          ? {
              ...k,
              ...patch,
              severity: patch.severity === 'high' ? 'high' : patch.severity === 'medium' ? 'medium' : k.severity,
            }
          : k,
      ),
    }))
  }, [])

  /** Removes a keyword rule. */
  const removeKeyword = useCallback((id) => {
    setSettings((prev) => ({
      ...prev,
      keywords: prev.keywords.filter((k) => k.id !== id),
    }))
  }, [])

  /** Restores only the keywords to the factory defaults. */
  const resetKeywords = useCallback(() => {
    setSettings((prev) => ({
      ...prev,
      keywords: structuredClone(DEFAULT_SUSPICIOUS_KEYWORDS),
    }))
  }, [])

  /** Updates the business hours (partial merge). */
  const setBusinessHours = useCallback((patch) => {
    setSettings((prev) => ({
      ...prev,
      businessHours: { ...prev.businessHours, ...patch },
    }))
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
      const current = prev.enrichment ?? { auto: { ip: false, url: false, hash: false }, ttlHours: 24, providers: {} }
      return {
        ...prev,
        enrichment: {
          ...current,
          ...patch,
          auto: { ...current.auto, ...(patch.auto ?? {}) },
          providers: { ...current.providers, ...(patch.providers ?? {}) },
        },
      }
    })
  }, [])

  const value = useMemo(
    () => ({
      keywords: settings.keywords,
      businessHours: settings.businessHours,
      iocAllowlist: settings.iocAllowlist,
      iocAllowlistDefault: settings.iocAllowlistDefault,
      reportBranding: settings.report,
      mailSettings: settings.mail,
      enrichmentSettings: settings.enrichment,
      addKeyword,
      updateKeyword,
      removeKeyword,
      resetKeywords,
      setBusinessHours,
      setIocAllowlist,
      setReportBranding,
      setMailSettings,
      setEnrichment,
    }),
    [
      settings,
      addKeyword,
      updateKeyword,
      removeKeyword,
      resetKeywords,
      setBusinessHours,
      setIocAllowlist,
      setReportBranding,
      setMailSettings,
      setEnrichment,
    ],
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
 * Hook that provides a memoized SOC detection engine, rebuilt only when the
 * keyword rules or the business hours change. The analysis components use it
 * to enrich events with `engine.analyze(entry)`.
 */
export function useSocEngine() {
  const { keywords, businessHours } = useSettings()
  return useMemo(
    // The user-editable keywords apply to every entry; the built-in command
    // and artifact rulesets add shell and filesystem/registry tradecraft
    // detection on top, each only for its own entry kind (see createSocEngine).
    () =>
      createSocEngine({
        keywords,
        commandKeywords: DEFAULT_COMMAND_KEYWORDS,
        artifactKeywords: DEFAULT_ARTIFACT_KEYWORDS,
        malwareKeywords: DEFAULT_MALWARE_KEYWORDS,
        businessHours,
      }),
    [keywords, businessHours],
  )
}
