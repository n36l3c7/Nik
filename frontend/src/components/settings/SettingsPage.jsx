import { useMemo, useRef, useState } from 'react'
import {
  Clock,
  DatabaseBackup,
  FileSearch,
  FileText,
  Fingerprint,
  HardDrive,
  KeyRound,
  Mail,
  Radar,
  ScrollText,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserCog,
  Users,
  X,
} from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { filterSettings, resolveSection, visibleSettings } from '../../domain/settingsNav.js'
import { useLayer } from '../../lib/layers.js'
import DetectionRulesSection from './sections/DetectionRulesSection.jsx'
import BusinessHoursSection from './sections/BusinessHoursSection.jsx'
import AccountsSection from './sections/AccountsSection.jsx'
import ApiKeysSection from './sections/ApiKeysSection.jsx'
import AuditLogSection from './sections/AuditLogSection.jsx'
import BackupSection from './sections/BackupSection.jsx'
import CapaRulesSection from './sections/CapaRulesSection.jsx'
import FlirtSignaturesSection from './sections/FlirtSignaturesSection.jsx'
import IocAllowlistSection from './sections/IocAllowlistSection.jsx'
import MailSettingsSection from './sections/MailSettingsSection.jsx'
import MyAccountSection from './sections/MyAccountSection.jsx'
import ReportBrandingSection from './sections/ReportBrandingSection.jsx'
import StorageSection from './sections/StorageSection.jsx'
import ThreatIntelSection from './sections/ThreatIntelSection.jsx'
import YaraRulesSection from './sections/YaraRulesSection.jsx'

/*
 * ============================================================================
 * SETTINGS — a page, with an address per section
 * ============================================================================
 *
 * The page takes the whole area next to the rail: on the left the sections,
 * in groups, with a box that narrows them by name and keyword; the section
 * itself at full width. Which sections exist, which permission each needs
 * and their addresses are in domain/settingsNav.js; this file gives each its
 * icon and its component.
 *
 * App owns the address: `section` is the id it read from /settings/<group>/
 * <section>, `onSection` goes to another, `onClose` leaves the page (so does
 * Escape, when no dialog is open over it, and the browser's Back).
 */

const SECTION_VIEWS = {
  detection: { icon: ShieldAlert, Component: DetectionRulesSection },
  hours: { icon: Clock, Component: BusinessHoursSection },
  mail: { icon: Mail, Component: MailSettingsSection },
  report: { icon: FileText, Component: ReportBrandingSection },
  allowlist: { icon: ShieldCheck, Component: IocAllowlistSection },
  intel: { icon: Radar, Component: ThreatIntelSection },
  yara: { icon: FileSearch, Component: YaraRulesSection },
  capa: { icon: Radar, Component: CapaRulesSection },
  flirt: { icon: Fingerprint, Component: FlirtSignaturesSection },
  account: { icon: UserCog, Component: MyAccountSection },
  accounts: { icon: Users, Component: AccountsSection },
  apikeys: { icon: KeyRound, Component: ApiKeysSection },
  storage: { icon: HardDrive, Component: StorageSection },
  backup: { icon: DatabaseBackup, Component: BackupSection },
  audit: { icon: ScrollText, Component: AuditLogSection },
}

/**
 * @param {{
 *   section: string | null,                 // the section the address names
 *   onSection: (id: string) => void,
 *   onClose: () => void,
 *   onOpenArtifact?: (id: string) => void,  // from Storage: open what fills the disk
 * }} props
 */
export default function SettingsPage({ section, onSection, onClose, onOpenArtifact }) {
  const { can } = useAuth()
  const [query, setQuery] = useState('')

  const groups = useMemo(() => visibleSettings(can), [can])
  const shown = useMemo(() => filterSettings(groups, query), [groups, query])
  // An address for a section this account cannot open shows its first one instead.
  const active = resolveSection(groups, section)
  const view = active ? SECTION_VIEWS[active.id] : null
  const ActiveComponent = view?.Component ?? null

  // Escape leaves the page only when nothing is open over it (a confirmation, a menu).
  const ref = useRef(null)
  useLayer(ref, { open: true, onClose, trap: false, page: true })

  return (
    <section
      ref={ref}
      aria-label="Settings"
      tabIndex={-1}
      className="flex min-w-0 flex-1 flex-col bg-canvas outline-none"
    >
      <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel px-6">
        <h1 className="text-sm font-semibold text-fg">
          Settings
          {active && <span className="font-normal text-fg-muted"> · {active.label}</span>}
        </h1>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close settings"
          title="Close settings (Esc)"
          className="p-1.5 text-fg-muted transition-colors hover:bg-canvas hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </header>

      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <div className="flex max-h-56 w-full shrink-0 flex-col border-b border-line bg-panel md:max-h-none md:w-60 md:border-b-0 md:border-r">
          <div className="border-b border-line-soft p-3">
            <label htmlFor="settings-search" className="sr-only">
              Find a setting
            </label>
            <div className="relative">
              <Search
                className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-fg-muted"
                aria-hidden="true"
              />
              <input
                id="settings-search"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Find a setting"
                autoComplete="off"
                className="w-full border border-line bg-canvas py-1.5 pl-8 pr-2 text-sm text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              />
            </div>
          </div>
          <nav aria-label="Settings sections" className="min-h-0 flex-1 space-y-4 overflow-y-auto p-3">
            {shown.length === 0 && (
              <p role="status" className="px-2 text-sm text-fg-muted">
                No section matches “{query.trim()}”.
              </p>
            )}
            {shown.map((group) => (
              <div key={group.id} role="group" aria-labelledby={`settings-group-${group.id}`}>
                <p
                  id={`settings-group-${group.id}`}
                  className="mb-1 px-2 font-mono text-[11px] uppercase tracking-wider text-fg-muted"
                >
                  {group.label}
                </p>
                <ul className="space-y-0.5">
                  {group.sections.map((item) => {
                    const Icon = SECTION_VIEWS[item.id].icon
                    const isActive = item.id === active?.id
                    return (
                      <li key={item.id}>
                        <button
                          type="button"
                          aria-current={isActive ? 'page' : undefined}
                          onClick={() => onSection(item.id)}
                          className={[
                            'flex w-full items-center gap-2 px-2 py-1.5 text-left text-sm font-medium transition-colors',
                            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                            isActive ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-canvas hover:text-fg',
                          ].join(' ')}
                        >
                          <Icon className="h-4 w-4 shrink-0" aria-hidden="true" />
                          {item.label}
                        </button>
                      </li>
                    )
                  })}
                </ul>
              </div>
            ))}
          </nav>
        </div>

        <div className="min-w-0 flex-1 overflow-y-auto p-6">
          {ActiveComponent && <ActiveComponent key={active.id} onOpenArtifact={onOpenArtifact} />}
        </div>
      </div>
    </section>
  )
}
