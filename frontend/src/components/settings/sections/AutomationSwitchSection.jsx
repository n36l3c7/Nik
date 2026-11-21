import { useEffect, useState } from 'react'
import { OctagonX } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useAutomation } from '../../../context/AutomationContext.jsx'
import { Badge, Button, Modal, Wait } from '../../ui/index.js'

/*
 * Automation → Stop all (admins): the general switch.
 *
 * Off: no playbook starts and no step is taken. Runs in progress keep their
 * state and go on from where they were when it is turned on again; a step
 * that was already talking to another system finishes. Turning it off and on
 * is written in the audit log.
 */

export default function AutomationSwitchSection() {
  const { setState } = useAutomation()
  const [current, setCurrent] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)

  useEffect(() => {
    let alive = true
    api
      .get('/automation/state')
      .then((found) => alive && setCurrent(found))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [])

  const set = async (enabled) => {
    setBusy(true)
    setError(null)
    try {
      const found = await api.put('/automation/state', { enabled })
      setCurrent(found)
      setState(found)
      setConfirming(false)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <OctagonX className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Stop all</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          One switch for every playbook. Stopped, nothing starts and no step is taken; runs in progress keep their place
          and go on when automation is started again.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {!current && !error && <Wait>Loading…</Wait>}

      {current && (
        <div className="max-w-xl space-y-4">
          <dl className="grid grid-cols-[10rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
            <dt className="text-fg-muted">Automation</dt>
            <dd>{current.enabled ? <Badge color="emerald">running</Badge> : <Badge color="red">stopped</Badge>}</dd>
            <dt className="text-fg-muted">Worker</dt>
            <dd>
              {current.workerAlive ? <Badge color="emerald">alive</Badge> : <Badge color="amber">not answering</Badge>}
              {!current.workerAlive && (
                <span className="mt-1 block text-xs text-fg-muted">
                  The “automation” container takes the steps of every run. While it is down, playbooks wait; check it
                  with your container tool.
                </span>
              )}
            </dd>
          </dl>
          {current.enabled ? (
            <Button variant="danger" icon={OctagonX} disabled={busy} onClick={() => setConfirming(true)}>
              Stop all automation
            </Button>
          ) : (
            <Button disabled={busy} onClick={() => set(true)}>
              Start automation again
            </Button>
          )}
        </div>
      )}

      <Modal
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Stop all automation?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={() => set(false)}>
              Stop all
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          No playbook will start and no step will be taken until an admin starts automation again. A step already
          talking to another system finishes; nothing is lost.
        </p>
      </Modal>
    </section>
  )
}
