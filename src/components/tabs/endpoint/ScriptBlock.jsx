import { useState } from 'react'
import { Check, Copy, Download } from 'lucide-react'

/*
 * Collection-script block: a copy/download-able code snippet the analyst runs
 * on the target host to produce an importable CSV. Used inside the Endpoint
 * Artifacts "where to find it" note for sources that are scripts to run rather
 * than files to copy.
 */

const LANG_META = {
  powershell: { label: 'PowerShell', ext: 'ps1' },
  bash: { label: 'Bash / sh', ext: 'sh' },
}

/**
 * @param {{ script: { lang: string, code: string }, filename: string }} props
 */
export default function ScriptBlock({ script, filename }) {
  const [copied, setCopied] = useState(false)
  const meta = LANG_META[script.lang] ?? { label: script.lang, ext: 'txt' }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(script.code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    } catch {
      /* insecure context: ignore */
    }
  }

  const handleDownload = () => {
    const blob = new Blob([script.code], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${filename}.${meta.ext}`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="mt-1.5 overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
      <div className="flex items-center justify-between gap-2 border-b border-slate-200 bg-slate-50 px-2.5 py-1.5 dark:border-slate-700 dark:bg-slate-800/60">
        <span className="text-[11px] font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {meta.label}
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-500 transition-colors hover:bg-slate-200 hover:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-200"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-emerald-500" /> Copied
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" /> Copy
              </>
            )}
          </button>
          <button
            type="button"
            onClick={handleDownload}
            className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] text-slate-500 transition-colors hover:bg-slate-200 hover:text-slate-700 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:text-slate-400 dark:hover:bg-slate-700 dark:hover:text-slate-200"
          >
            <Download className="h-3 w-3" /> Download
          </button>
        </div>
      </div>
      <pre className="max-h-64 overflow-auto bg-slate-900 p-3 text-[11px] leading-relaxed text-slate-100 dark:bg-slate-950">
        <code>{script.code}</code>
      </pre>
    </div>
  )
}
