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
    <div className="mt-1.5 overflow-hidden border border-line">
      <div className="flex items-center justify-between gap-2 border-b border-line bg-canvas px-2.5 py-1.5">
        <span className="text-[11px] font-medium uppercase tracking-wide text-fg-muted">{meta.label}</span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-accent" /> Copied
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
            className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Download className="h-3 w-3" /> Download
          </button>
        </div>
      </div>
      <pre className="max-h-64 overflow-auto bg-panel p-3 text-[11px] leading-relaxed text-fg-subtle">
        <code>{script.code}</code>
      </pre>
    </div>
  )
}
