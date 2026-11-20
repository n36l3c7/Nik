import { useCallback, useEffect, useState } from 'react'
import { LogOut, MonitorSmartphone } from 'lucide-react'
import { formatRelative } from '../../lib/time.js'
import { browserName } from '../../domain/signin.js'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { Badge, Button, Wait } from '../ui/index.js'
import { ErrorNote } from '../auth/SecondFactorParts.jsx'

/*
 * The open sessions of an account: one's own under My account, anybody's for
 * an administrator. Each says the browser, the address it came from, when it
 * began and when it was last used; "End" ends it at once (its next request is
 * refused).
 *
 * @param {{
 *   load: () => Promise<{ sessions: object[] }>,
 *   end: (session: object) => Promise<unknown>,   // end one
 *   endOthers?: (() => Promise<unknown>) | null,  // end all but the caller's own, when offered
 *   endOthersLabel?: string,
 *   own?: boolean,                                // the list is the caller's own account
 *   version?: number,                             // raised by who knows the sessions changed: read again
 *   label: string,                                // the accessible name of the list
 * }} props
 */
export default function SessionsList({
  load,
  end,
  endOthers = null,
  endOthersLabel = 'End all the others',
  own = false,
  version = 0,
  label,
}) {
  const [sessions, setSessions] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(null) // the id being ended, or 'others'
  const menu = useObjectMenu()

  const refresh = useCallback(async () => {
    try {
      setSessions((await load()).sessions)
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [load])
  useEffect(() => {
    refresh()
  }, [refresh, version])

  const act = async (key, action) => {
    if (busy) return
    setBusy(key)
    setError(null)
    try {
      await action()
      await refresh()
    } catch (failure) {
      setError(failure.message)
    }
    setBusy(null)
  }

  if (sessions === null) return error ? <ErrorNote>{error}</ErrorNote> : <Wait>Reading the sessions…</Wait>
  const others = sessions.filter((session) => !session.current)

  return (
    <div className="space-y-3">
      {error && <ErrorNote>{error}</ErrorNote>}
      {sessions.length === 0 ? (
        <p className="text-sm text-fg-muted">No open session.</p>
      ) : (
        <ul aria-label={label} className="divide-y divide-line-soft border border-line">
          {sessions.map((session) => {
            const name = browserName(session.userAgent)
            const endLabel = session.current && own ? 'Sign out' : 'End'
            return (
              <li
                key={session.id}
                className="flex items-center justify-between gap-3 px-3 py-2.5"
                onContextMenu={(event) =>
                  menu(event, {
                    title: name,
                    copy: [
                      { label: 'Copy the address', text: session.address },
                      { label: 'Copy the browser as it names itself', text: session.userAgent },
                    ],
                    danger: [
                      {
                        label: session.current && own ? 'Sign out' : 'End this session',
                        icon: LogOut,
                        onSelect: () => act(session.id, () => end(session)),
                      },
                    ],
                  })
                }
              >
                <div className="flex min-w-0 items-start gap-2">
                  <MonitorSmartphone className="mt-0.5 h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
                  <div className="min-w-0">
                    <p className="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                      <span className="truncate" title={session.userAgent}>
                        {name}
                      </span>
                      {session.current && <Badge color="cyan">{own ? 'This browser' : 'Your session'}</Badge>}
                    </p>
                    <p className="mt-0.5 text-xs text-fg-muted">
                      From <span className="font-mono">{session.address || 'an unknown address'}</span> · began{' '}
                      {formatRelative(session.createdAt)} · last used {formatRelative(session.lastUsedAt)}
                    </p>
                  </div>
                </div>
                <Button
                  variant="secondary"
                  size="xs"
                  icon={LogOut}
                  waiting={busy === session.id}
                  disabled={busy !== null}
                  aria-label={`${endLabel}: ${name} from ${session.address || 'an unknown address'}`}
                  onClick={() => act(session.id, () => end(session))}
                >
                  {endLabel}
                </Button>
              </li>
            )
          })}
        </ul>
      )}
      {endOthers && (
        <Button
          variant="secondary"
          size="sm"
          icon={LogOut}
          waiting={busy === 'others'}
          disabled={busy !== null || others.length === 0}
          title={others.length === 0 ? 'There is no other session' : undefined}
          onClick={() => act('others', endOthers)}
        >
          {endOthersLabel}
        </Button>
      )}
    </div>
  )
}
