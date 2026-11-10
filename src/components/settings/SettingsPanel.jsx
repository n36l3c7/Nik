import { useEffect } from 'react'
import {
  Clock,
  FileSearch,
  Fingerprint,
  KeyRound,
  Radar,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Users,
  X,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import DetectionRulesSection from './sections/DetectionRulesSection.jsx'
import BusinessHoursSection from './sections/BusinessHoursSection.jsx'
import IocAllowlistSection from './sections/IocAllowlistSection.jsx'
import AccountsSection from './sections/AccountsSection.jsx'
import ApiKeysSection from './sections/ApiKeysSection.jsx'
import AuditLogSection from './sections/AuditLogSection.jsx'
import YaraRulesSection from './sections/YaraRulesSection.jsx'
import FlirtSignaturesSection from './sections/FlirtSignaturesSection.jsx'
import CapaRulesSection from './sections/CapaRulesSection.jsx'

/*
 * ============================================================================
 * SETTINGS PANEL — one home for platform configuration
 * ============================================================================
 *
 * A large, sectioned dialog replacing the old cramped settings/users/audit
 * modals. Sections (left nav): Detection rules, Business hours, IOC allowlist, Accounts
 * (admin only), Audit log. The active section is owned by App so the header
 * and sidebar buttons can deep-link into a specific section.
 */

const SECTIONS = [
  { id: 'detection', label: 'Detection rules', icon: ShieldAlert, Component: DetectionRulesSection },
  { id: 'hours', label: 'Business hours', icon: Clock, Component: BusinessHoursSection },
  { id: 'allowlist', label: 'IOC allowlist', icon: ShieldCheck, Component: IocAllowlistSection },
  { id: 'accounts', label: 'Accounts', icon: Users, Component: AccountsSection, adminOnly: true },
  { id: 'apikeys', label: 'API keys', icon: KeyRound, Component: ApiKeysSection, adminOnly: true },
  { id: 'yara', label: 'YARA rules', icon: FileSearch, Component: YaraRulesSection, adminOnly: true },
  { id: 'flirt', label: 'FLIRT signatures', icon: Fingerprint, Component: FlirtSignaturesSection, adminOnly: true },
  { id: 'capa', label: 'capa rules', icon: Radar, Component: CapaRulesSection, adminOnly: true },
  { id: 'audit', label: 'Audit log', icon: ScrollText, Component: AuditLogSection },
]

/**
 * @param {{
 *   open: boolean,
 *   onClose: () => void,
 *   section?: string,
 *   onSectionChange?: (id: string) => void,
 * }} props
 */
export default function SettingsPanel({ open, onClose, section = 'detection', onSectionChange }) {
  const { currentUser } = useAuth()
  const isAdmin = currentUser?.role === 'admin'

  const visibleSections = SECTIONS.filter((s) => !s.adminOnly || isAdmin)
  // Guard against a hidden section being selected (e.g. non-admin deep-link).
  const activeId = visibleSections.some((s) => s.id === section) ? section : visibleSections[0].id
  const active = visibleSections.find((s) => s.id === activeId) ?? visibleSections[0]
  const ActiveComponent = active.Component

  useEffect(() => {
    if (!open) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') onClose?.()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Settings"
      className="fixed inset-0 z-50 flex items-center justify-center bg-panel p-4 backdrop-blur-sm"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose?.()
      }}
    >
      <div className="flex h-[85vh] w-full max-w-5xl flex-col overflow-hidden border border-line bg-panel shadow-2xl">
        {/* Header */}
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
          <h2 className="text-sm font-semibold text-fg">Settings</h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="p-1 text-fg-muted transition-colors hover:bg-canvas hover:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </header>

        {/* Body: left nav + scrollable content */}
        <div className="flex min-h-0 flex-1">
          <nav
            aria-label="Settings sections"
            className="w-48 shrink-0 space-y-1 overflow-y-auto border-r border-line p-3"
          >
            {visibleSections.map((s) => {
              const Icon = s.icon
              const isActive = s.id === activeId
              return (
                <button
                  key={s.id}
                  type="button"
                  aria-current={isActive ? 'page' : undefined}
                  onClick={() => onSectionChange?.(s.id)}
                  className={[
                    'flex w-full items-center gap-2 px-3 py-2 text-left text-sm font-medium transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                    isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-canvas',
                  ].join(' ')}
                >
                  <Icon className="h-4 w-4 shrink-0" />
                  {s.label}
                </button>
              )
            })}
          </nav>

          <div className="min-w-0 flex-1 overflow-y-auto p-5">
            <ActiveComponent />
          </div>
        </div>
      </div>
    </div>
  )
}
