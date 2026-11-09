import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, Fingerprint, Power, Trash2, Upload } from 'lucide-react'
import { api, upload } from '../../../services/api.js'
import { formatBytes } from '../../../utils/events.js'
import { formatRelative } from '../../../utils/time.js'
import { Badge, Button, MicroSkull } from '../../ui/index.js'

/*
 * FLIRT signatures settings section (admin only). The analyzer worker applies
 * rizin's bundled signatures; admins add compiled signatures (.sig) or
 * pattern files (.pat) for the libraries their samples link, e.g. a Rust
 * toolchain's crates built with the same compiler. Enabled signatures apply
 * from the next disassembly of each sample.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 font-mono text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

export default function FlirtSignaturesSection() {
  const [signatures, setSignatures] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [name, setName] = useState('')
  const [file, setFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [formKey, setFormKey] = useState(0)

  const load = useCallback(async () => {
    try {
      setSignatures((await api.get('/flirt-signatures')).signatures)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const submit = async (event) => {
    event.preventDefault()
    setUploading(true)
    setError(null)
    try {
      await upload('/flirt-signatures', file, { fields: { name: name.trim() } })
      setName('')
      setFile(null)
      setFormKey((k) => k + 1) // clears the file input
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setUploading(false)
    }
  }

  const toggle = async (signature) => {
    setError(null)
    try {
      await api.put(`/flirt-signatures/${signature.id}`, { name: signature.name, enabled: !signature.enabled })
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  const remove = async (signature) => {
    setError(null)
    try {
      await api.del(`/flirt-signatures/${signature.id}`)
      await load()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <Fingerprint className="h-4 w-4 text-accent" aria-hidden="true" />
          FLIRT signatures
        </h2>
        <p className="mt-1 text-sm text-fg-muted">
          Library code the analyzer recognises is hidden by default in a sample&apos;s Code view. rizin ships signatures
          for common C runtimes; upload a compiled signature (<code>.sig</code>) or a pattern file (<code>.pat</code>)
          to recognise more, e.g. the crates of a Rust toolchain. Signatures apply from the next disassembly: use{' '}
          <em>Re-analyse</em> on samples already disassembled.
        </p>
      </div>

      {error && (
        <p
          role="alert"
          className="flex items-center gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
        >
          <AlertCircle className="h-4 w-4 shrink-0" aria-hidden="true" />
          {error}
        </p>
      )}

      <form key={formKey} onSubmit={submit} className="space-y-3 border border-line bg-canvas p-3">
        <div>
          <label htmlFor="flirt-name" className="mb-1 block font-mono text-xs text-fg-muted">
            Name
          </label>
          <input
            id="flirt-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="e.g. tokio 1.38 (rustc 1.79, x86_64-pc-windows-msvc)"
            maxLength={120}
            className={INPUT_CLASS}
            required
          />
        </div>
        <div>
          <label htmlFor="flirt-file" className="mb-1 block font-mono text-xs text-fg-muted">
            Signature file (.sig or .pat, up to 32 MB)
          </label>
          <input
            id="flirt-file"
            type="file"
            accept=".sig,.pat"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
            className="block font-mono text-xs text-fg-muted file:mr-3 file:border file:border-line file:bg-panel file:px-3 file:py-1.5 file:text-fg"
            required
          />
        </div>
        <Button type="submit" size="sm" icon={Upload} disabled={uploading || !file || !name.trim()}>
          {uploading ? 'Uploading…' : 'Upload signature'}
        </Button>
      </form>

      <div className="space-y-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">
          Uploaded signatures · {signatures.length}
        </h3>
        {loading ? (
          <p className="flex items-center gap-2 font-mono text-sm text-fg-muted">
            <MicroSkull /> loading…
          </p>
        ) : signatures.length === 0 ? (
          <p className="text-sm text-fg-muted">None yet: only rizin&apos;s bundled signatures are applied.</p>
        ) : (
          <ul className="space-y-2">
            {signatures.map((signature) => (
              <li
                key={signature.id}
                className="flex flex-wrap items-center justify-between gap-2 border border-line bg-panel px-3 py-2.5"
              >
                <span className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-sm">
                  <span className="font-semibold text-fg">{signature.name}</span>
                  <Badge color={signature.enabled ? 'emerald' : 'slate'}>
                    {signature.enabled ? 'enabled' : 'disabled'}
                  </Badge>
                  <span className="text-xs text-fg-muted">
                    {signature.fileName} · {formatBytes(signature.size)} · {signature.createdBy} ·{' '}
                    {formatRelative(signature.updatedAt)}
                  </span>
                </span>
                <span className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Power}
                    onClick={() => toggle(signature)}
                    aria-label={`${signature.enabled ? 'Disable' : 'Enable'} ${signature.name}`}
                  >
                    {signature.enabled ? 'Disable' : 'Enable'}
                  </Button>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Trash2}
                    onClick={() => remove(signature)}
                    aria-label={`Delete ${signature.name}`}
                  >
                    Delete
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  )
}
