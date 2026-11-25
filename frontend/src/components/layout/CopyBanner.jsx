/**
 * The thin strip over the whole app on a server that is a copy of another (a restored backup to look
 * at): nothing here sends anything out, and it says so wherever the person is. `server` is what
 * `GET /auth/me` says (`{ copy, copyOf }`, context/AuthContext.jsx); nothing is drawn for a real server.
 */
export default function CopyBanner({ server }) {
  if (!server?.copy) return null
  return (
    <div
      role="status"
      className="fixed inset-x-0 top-0 z-[60] flex h-7 items-center justify-center gap-2 border-b border-med-line bg-med-soft px-4 font-mono text-xs text-med-fg"
    >
      <span className="font-semibold">COPY of {server.copyOf || 'another server'}</span>
      <span aria-hidden="true">·</span>
      <span>nothing leaves this server</span>
    </div>
  )
}
