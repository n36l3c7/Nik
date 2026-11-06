import { useEffect, useState } from 'react'
import { BookOpen } from 'lucide-react'
import { api } from '../../services/api.js'
import pkg from '../../../package.json'

/*
 * ============================================================================
 * AUTH LAYOUT — shared frame of the sign-in and first-run screens
 * ============================================================================
 * Left: the NIK banner and a `$ nik status` box with REAL checks — the API
 * (GET /api/health, with its round-trip time) and the database
 * (GET /api/ready). Both endpoints are public, so this works before sign-in.
 * Right: the form passed as children.
 */

// Shared form styling for the auth screens.
export const AUTH_INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2.5 font-mono text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
export const AUTH_LABEL_CLASS = 'mb-1.5 block font-mono text-xs text-fg-muted'

const BANNER = [
  '███╗   ██╗██╗██╗  ██╗',
  '████╗  ██║██║██║ ██╔╝',
  '██╔██╗ ██║██║█████╔╝ ',
  '██║╚██╗██║██║██╔═██╗ ',
  '██║ ╚████║██║██║  ██╗',
  '╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝',
].join('\n')

/** Probe one public endpoint: { ok, ms } (ok null while pending). */
function useProbe(path) {
  const [state, setState] = useState({ ok: null, ms: null })
  useEffect(() => {
    let cancelled = false
    const started = performance.now()
    api
      .get(path)
      .then(() => !cancelled && setState({ ok: true, ms: Math.round(performance.now() - started) }))
      .catch(() => !cancelled && setState({ ok: false, ms: null }))
    return () => {
      cancelled = true
    }
  }, [path])
  return state
}

function StatusLine({ label, probe, okText }) {
  const color = probe.ok === null ? 'text-med' : probe.ok ? 'text-accent' : 'text-high'
  const text = probe.ok === null ? 'checking…' : probe.ok ? okText(probe) : 'unreachable'
  return (
    <span className="whitespace-pre">
      <span className={color} aria-hidden="true">●</span> {label.padEnd(10)} {text}
    </span>
  )
}

/**
 * @param {{ title: string, subtitle: string, children: import('react').ReactNode }} props
 */
export default function AuthLayout({ title, subtitle, children }) {
  const apiProbe = useProbe('/health')
  const db = useProbe('/ready')

  return (
    <div className="flex min-h-screen flex-wrap bg-canvas">
      <section
        aria-label="About Nik"
        className="flex min-w-0 flex-[1_1_520px] flex-col justify-center gap-6 border-line bg-sunken px-8 py-12 font-mono md:border-r md:px-12"
      >
        <pre aria-hidden="true" className="m-0 text-[clamp(12px,1.5vw,18px)] leading-[1.2] text-accent">
          {BANNER}
        </pre>
        <p className="text-base text-fg">
          forensic analysis platform <span className="text-fg-muted">v{pkg.version}</span>
        </p>
        <div role="status" className="flex max-w-lg flex-col gap-1 border border-line bg-canvas px-4 py-3 text-[13px] text-fg-muted">
          <span>$ nik status</span>
          <StatusLine label="api" probe={apiProbe} okText={(p) => `online   · ${p.ms} ms`} />
          <StatusLine label="database" probe={db} okText={() => 'ready'} />
        </div>
        <p className="max-w-lg text-xs text-fg-muted">
          Raw forensic files are parsed in your browser; only normalized entries reach the server.
          Every action is recorded in the audit log under your name.
        </p>
      </section>

      <main className="flex min-w-0 flex-[1_1_420px] items-center justify-center px-8 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-6 font-mono">
            <h1 className="text-2xl font-extrabold text-fg">{title}</h1>
            <p className="mt-1 text-sm text-fg-muted">{subtitle}</p>
          </div>
          {children}
          <p className="mt-6 border-t border-line pt-4 text-xs text-fg-muted">
            <a href="/api/docs" className="inline-flex items-center gap-1 text-link hover:text-link-fg hover:underline">
              <BookOpen className="h-3.5 w-3.5" aria-hidden="true" />
              API documentation
            </a>
          </p>
        </div>
      </main>
    </div>
  )
}
