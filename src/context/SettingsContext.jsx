import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import {
  DEFAULT_SUSPICIOUS_KEYWORDS,
  DEFAULT_BUSINESS_HOURS,
} from '../config/detectionRules.js'
import { api } from '../services/api.js'
import { createSocEngine } from '../utils/soc.js'
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
  return (
    crypto.randomUUID?.() ?? `kw-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  )
}

/** True if `pattern` is a valid RegExp (used by the UI to validate input). */
export function isValidRegex(pattern) {
  try {
    // eslint-disable-next-line no-new
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
  }
}

/** Normalize a settings document coming from the server. */
function normalizeSettings(doc) {
  return {
    keywords: Array.isArray(doc?.keywords)
      ? doc.keywords
      : structuredClone(DEFAULT_SUSPICIOUS_KEYWORDS),
    businessHours: {
      ...DEFAULT_BUSINESS_HOURS,
      ...(doc?.businessHours ?? {}),
    },
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
              severity:
                patch.severity === 'high'
                  ? 'high'
                  : patch.severity === 'medium'
                    ? 'medium'
                    : k.severity,
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

  const value = useMemo(
    () => ({
      keywords: settings.keywords,
      businessHours: settings.businessHours,
      addKeyword,
      updateKeyword,
      removeKeyword,
      resetKeywords,
      setBusinessHours,
    }),
    [settings, addKeyword, updateKeyword, removeKeyword, resetKeywords, setBusinessHours],
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
    () => createSocEngine({ keywords, businessHours }),
    [keywords, businessHours],
  )
}
