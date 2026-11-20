import { useCallback, useEffect, useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, RotateCcw, Save, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { api } from '../../../services/api.js'
import { ROLES, roleLabel } from '../../../domain/permissions.js'
import { accountsToEnrol, minutesWords, policyChanges, policyForm } from '../../../domain/signin.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button, Modal, Wait } from '../../ui/index.js'
import { ErrorNote } from '../../auth/SecondFactorParts.jsx'

/*
 * Access → Sign-in and sessions (admins): the sign-in policy of the server.
 *
 *  - which roles must have a second factor;
 *  - how long a session lives, unused and at most;
 *  - the waits after failed sign-ins;
 *  - the networks administrators are accepted from, with what the server sees
 *    of where the administrator is now. When it cannot know where its clients
 *    are, the screen says so and why, and the list is refused.
 *
 * One Save for the whole form. A list of networks that would refuse whoever
 * saves it is not saved before they said they want that.
 */

const INPUT_CLASS =
  'w-28 border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const HEADING_CLASS = 'mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted'
const BREAK_GLASS = 'python -m app.account clear-admin-networks'

function NumberField({ id, label, unit, hint, value, onChange, problem }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1.5 block text-sm font-medium text-fg">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <input
          id={id}
          type="text"
          inputMode="numeric"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          aria-invalid={problem ? 'true' : undefined}
          aria-describedby={`${id}-hint`}
          className={`${INPUT_CLASS} ${problem ? 'border-high-line' : ''}`}
        />
        <span className="text-sm text-fg-muted">{unit}</span>
      </div>
      <p id={`${id}-hint`} className={`mt-1 text-xs ${problem ? 'text-high-fg' : 'text-fg-muted'}`}>
        {problem || hint}
      </p>
    </div>
  )
}

/** What the server sees of where the administrator is, and whether that is worth anything. */
function AddressSeen({ address }) {
  return (
    <div className="space-y-2">
      <p className="text-sm text-fg-muted">
        The server sees you at{' '}
        <span aria-label="Your address as the server sees it" className="font-mono text-fg">
          {address.address || 'an address it cannot read'}
        </span>
        {address.throughProxy
          ? `, as the web container (${address.connection}) reports it.`
          : ', the address of the connection itself.'}
      </p>
      {!address.knowable && (
        <div
          role="alert"
          className="flex items-start gap-2 border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>
            The restriction cannot work on this server as it is set up. {address.reason} A list saved here would refuse
            every administrator, or let everybody in if it held that address. The waits after failed sign-ins are
            counted per account only, for the same reason. The deployment guide says what to change.
          </span>
        </div>
      )}
      {address.overtrusting && (
        <div
          role="alert"
          className="flex items-start gap-2 border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>
            This server is started with FORWARDED_ALLOW_IPS=*: it believes the address written in a request by whoever
            sends it, not only by its web container. Set it empty, as the Compose file of this release does.
          </span>
        </div>
      )}
      <p className="text-xs text-fg-muted">
        Forwarded addresses are believed from:{' '}
        <span className="font-mono">{address.trustedProxies.join(', ') || 'nobody'}</span> (TRUSTED_PROXIES, in the
        environment of the api container).
      </p>
    </div>
  )
}

export default function SignInPolicySection() {
  const { users, currentUser, refreshMe, refreshUsers, checkSession } = useAuth()
  const [found, setFound] = useState(null) // { policy, defaults, recommended, limits, address }
  const [form, setForm] = useState(null)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [asking, setAsking] = useState(null) // { code, message }: the server wants to hear it twice

  const load = useCallback(async () => {
    try {
      const answer = await api.get('/auth/policy')
      setFound(answer)
      setForm(policyForm(answer.policy))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const { body, problems } = useMemo(
    () => (found && form ? policyChanges(form, found.policy, found.limits) : { body: {}, problems: {} }),
    [found, form],
  )
  const dirty = Object.keys(body).length > 0
  const wrong = Object.keys(problems).length > 0

  const save = async (confirm = false) => {
    if (saving || wrong || !dirty) return false
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const answer = await api.put('/auth/policy', confirm ? { ...body, confirm: true } : body)
      setFound(answer)
      setForm(policyForm(answer.policy))
      setAsking(null)
      setSaved(true)
      // The times of this session may have changed, and so may what is asked of this account and of the others.
      await Promise.all([refreshMe(), refreshUsers(), checkSession()])
      setSaving(false)
      return true
    } catch (failure) {
      setSaving(false)
      if (failure.status === 409 && failure.code) setAsking({ code: failure.code, message: failure.message })
      else setError(failure.message)
      return false
    }
  }

  useUnsavedChanges(dirty, { what: 'The sign-in policy', save: wrong ? undefined : () => save() })
  const pageMenu = usePageMenu(() => [
    {
      label: 'Save',
      icon: Save,
      disabled: !dirty || wrong || saving,
      title: !dirty ? 'Nothing was changed' : wrong ? 'Something in the form cannot be saved' : undefined,
      onSelect: () => save(),
    },
  ])

  if (!found || !form) {
    return (
      <section className="space-y-4">
        <Header />
        {error ? <ErrorNote>{error}</ErrorNote> : <Wait>Reading the policy…</Wait>}
      </section>
    )
  }

  const set = (name) => (value) => {
    setSaved(false)
    setForm((old) => ({ ...old, [name]: value }))
  }
  const toggleRole = (role, on) =>
    set('requiredRoles')(on ? [...form.requiredRoles, role] : form.requiredRoles.filter((id) => id !== role))
  const toEnrol = accountsToEnrol(users, form.requiredRoles)
  const meToo = toEnrol.some((user) => user.id === currentUser?.id)
  const number = (name, label, unit, hint) => (
    <NumberField
      id={`policy-${name}`}
      label={label}
      unit={unit}
      hint={hint}
      value={form[name]}
      onChange={set(name)}
      problem={problems[name]}
    />
  )
  const { defaults, recommended } = found

  return (
    <section className="max-w-3xl space-y-8" onContextMenu={pageMenu}>
      <Header />

      <div>
        <h3 className={HEADING_CLASS}>Second factor</h3>
        <fieldset>
          <legend className="mb-2 text-sm text-fg-muted">
            The accounts of these roles must have a second factor (a code from an authenticator app, asked after the
            password). One that has none is led to set it up at its next request, and can do nothing else before. API
            keys are not asked: a key is a credential of its own.
          </legend>
          <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {ROLES.filter((role) => role.shown).map((role) => (
              <label key={role.id} className="flex items-center gap-2 text-sm text-fg">
                <input
                  type="checkbox"
                  checked={form.requiredRoles.includes(role.id)}
                  onChange={(event) => toggleRole(role.id, event.target.checked)}
                  className="accent-[var(--color-accent)]"
                />
                <span>{roleLabel(role.id)}</span>
                {recommended.requiredRoles.includes(role.id) && <Badge color="cyan">Recommended</Badge>}
              </label>
            ))}
          </div>
        </fieldset>
        {form.requiredRoles.length > 0 && (
          <p role="status" className="mt-3 text-sm text-fg-muted">
            {toEnrol.length === 0
              ? 'Every account of these roles has a second factor already.'
              : `${toEnrol.length} account${toEnrol.length === 1 ? ' has' : 's have'} none and will be asked to set one up: ${toEnrol
                  .slice(0, 8)
                  .map((user) => user.username)
                  .join(', ')}${toEnrol.length > 8 ? '…' : ''}.`}
            {meToo && ' You are one of them: you will set yours up as soon as this is saved.'}
          </p>
        )}
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Sessions</h3>
        <p className="mb-3 text-sm text-fg-muted">
          A session ends when nothing was done in it for a while, and in any case some hours after the sign-in. The
          person is warned a minute before, and what is on screen stays when it ends. What the page asks by itself
          (lists that refresh) does not count as use.
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {number(
            'idleMinutes',
            'Unused for',
            'minutes',
            `0 for never. ${minutesWords(defaults.idleMinutes)} at first.`,
          )}
          {number(
            'idleMinutesAdmin',
            'Unused for, administrators',
            'minutes',
            `Recommended: ${recommended.idleMinutesAdmin}. ${minutesWords(defaults.idleMinutesAdmin)} at first.`,
          )}
          {number(
            'lifetimeHours',
            'At most',
            'hours',
            `After the sign-in, used or not. ${defaults.lifetimeHours} at first.`,
          )}
        </div>
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Failed sign-ins</h3>
        <p className="mb-3 text-sm text-fg-muted">
          Wrong passwords and wrong codes are counted in a row, per account and per address. Past the number below the
          next attempt waits, twice as long after each further failure, up to the longest wait; the count falls back
          with time and on a good sign-in. Nothing is locked for good, and the addresses an account last signed in from
          do not wait for somebody else&apos;s guesses.
        </p>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {number(
            'attemptsBeforeWait',
            'Failures before a wait',
            'in a row',
            `${defaults.attemptsBeforeWait} at first.`,
          )}
          {number('firstWaitSeconds', 'First wait', 'seconds', `${defaults.firstWaitSeconds} at first.`)}
          {number('maxWaitMinutes', 'Longest wait', 'minutes', `${defaults.maxWaitMinutes} at first.`)}
          {number(
            'notifyAfter',
            'Tell the administrators after',
            'failures in a row',
            `One notice per run of failures. ${defaults.notifyAfter} at first.`,
          )}
        </div>
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Administrators&apos; networks</h3>
        <p className="mb-3 text-sm text-fg-muted">
          When networks are listed here, the accounts that hold the admin role sign in and work only from them; from
          elsewhere they are refused, after the password and the code were right. It applies to API keys that hold the
          admin role too. Left empty, administrators sign in from anywhere.
        </p>
        <label htmlFor="policy-adminNetworks" className="mb-1.5 block text-sm font-medium text-fg">
          Networks, one per line
        </label>
        <textarea
          id="policy-adminNetworks"
          rows={4}
          value={form.adminNetworks}
          onChange={(event) => set('adminNetworks')(event.target.value)}
          placeholder={'10.20.0.0/16\n2001:db8:aa::/48\n192.0.2.7'}
          spellCheck={false}
          aria-invalid={problems.adminNetworks ? 'true' : undefined}
          aria-describedby="policy-adminNetworks-hint"
          className={`w-full max-w-md border bg-panel px-3 py-2 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
            problems.adminNetworks ? 'border-high-line' : 'border-line'
          }`}
        />
        <p
          id="policy-adminNetworks-hint"
          className={`mb-3 mt-1 text-xs ${problems.adminNetworks ? 'text-high-fg' : 'text-fg-muted'}`}
        >
          {problems.adminNetworks || 'IPv4 or IPv6, as a network (10.20.0.0/16) or a single address.'}
        </p>
        <AddressSeen address={found.address} />
      </div>

      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
        <Button waiting={saving} icon={Save} onClick={() => save()} disabled={saving || !dirty || wrong}>
          {saving ? 'Saving…' : 'Save'}
        </Button>
        <Button
          variant="ghost"
          icon={RotateCcw}
          onClick={() => {
            setForm(policyForm(found.policy))
            setSaved(false)
          }}
          disabled={saving || !dirty}
        >
          Undo the changes
        </Button>
        {saved && !dirty && (
          <p role="status" className="flex items-center gap-2 text-sm text-fg">
            <CheckCircle2 className="h-4 w-4 text-accent" aria-hidden="true" />
            Saved.
          </p>
        )}
      </div>

      {asking && (
        <Modal
          open
          onClose={() => setAsking(null)}
          title="This list would refuse you"
          maxWidth="max-w-lg"
          footer={
            <>
              <Button variant="ghost" onClick={() => setAsking(null)} disabled={saving}>
                Do not save
              </Button>
              <Button waiting={saving} variant="danger" onClick={() => save(true)} disabled={saving}>
                {saving ? 'Saving…' : 'Save it anyway'}
              </Button>
            </>
          }
        >
          <div className="space-y-2 text-sm text-fg-muted">
            <p className="text-fg">{asking.message}</p>
            <p>
              Saved anyway, the list is in force at once: this page stops answering you, and so does everything else,
              until you are on one of its networks. If no administrator can get there, the list is emptied from the
              server itself, with <span className="font-mono text-fg">{BREAK_GLASS}</span> in the api container.
            </p>
          </div>
        </Modal>
      )}
    </section>
  )
}

function Header() {
  return (
    <div>
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-accent" aria-hidden="true" />
        <h2 className="text-base font-semibold text-fg">Sign-in and sessions</h2>
      </div>
      <p className="mt-1 max-w-prose text-sm text-fg-muted">
        Who must have a second factor, how long a session lives, what failed sign-ins cost, and where administrators may
        sign in from. No role is asked for a second factor and no network is listed until it is set here.
      </p>
    </div>
  )
}
