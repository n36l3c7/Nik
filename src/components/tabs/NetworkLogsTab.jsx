import { Eye, Globe, Info, Network, Plus, ShieldCheck } from 'lucide-react'
import { Badge, Button, EmptyState } from '../ui'

/*
 * "Network Logs" tab — polished placeholder, ready for expansion.
 * The incident data structure (data.network) is already registered in
 * config/tabs.js: to implement the real analysis just replace this
 * component. See README.md § "Adding a new analysis tab".
 */

/** Planned analysis modules, shown as disabled mini-cards. */
const UPCOMING_MODULES = [
  {
    id: 'pcap',
    title: 'PCAP Viewer',
    icon: Eye,
    description: 'Packet inspection from network captures (.pcap/.pcapng).',
  },
  {
    id: 'firewall',
    title: 'Firewall Logs',
    icon: ShieldCheck,
    description: 'Firewall log analysis: blocked connections and triggered rules.',
  },
  {
    id: 'proxy-dns',
    title: 'Proxy/DNS',
    icon: Globe,
    description: 'Correlation of proxy requests and suspicious DNS queries.',
  },
]

/**
 * @param {{ incident: object }} props — the active incident (reserved for
 * future implementation: data will live in incident.data.network)
 */
export default function NetworkLogsTab({ incident }) {
  return (
    <div className="mx-auto max-w-4xl space-y-6">
      {/* Main empty state with the message required by the SPEC */}
      <div className="rounded-xl border border-slate-200 bg-white py-10 dark:border-slate-800 dark:bg-slate-900">
        <EmptyState
          icon={Network}
          title="Network Logs Analysis"
          message="Ready for expansion: section dedicated to analyzing PCAP files, firewall or proxy logs."
        />
      </div>

      {/* Mini-cards for upcoming modules: disabled and dashed */}
      <div className="grid gap-4 sm:grid-cols-3">
        {UPCOMING_MODULES.map(({ id, title, icon: Icon, description }) => (
          <div
            key={id}
            aria-disabled="true"
            className="select-none rounded-xl border border-dashed border-slate-300 bg-white/60 p-4 opacity-70 dark:border-slate-700 dark:bg-slate-900/60"
          >
            <div className="flex items-center gap-2">
              <span className="rounded-lg bg-slate-100 p-2 text-slate-400 dark:bg-slate-800 dark:text-slate-500">
                <Icon size={18} />
              </span>
              <span className="min-w-0 truncate text-sm font-medium text-slate-600 dark:text-slate-300">
                {title}
              </span>
              <Badge color="slate" className="ml-auto shrink-0">
                Coming soon
              </Badge>
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              {description}
            </p>
          </div>
        ))}
      </div>

      {/* Future action: intentionally disabled */}
      <div className="flex justify-center">
        <Button variant="secondary" icon={Plus} disabled>
          Add data source (coming soon)
        </Button>
      </div>

      {/* Pointer to the developer guide */}
      <p className="flex items-center justify-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
        <Info size={14} className="shrink-0" />
        To implement this tab see README.md § &#39;Adding a new analysis
        tab&#39;.
      </p>
    </div>
  )
}
