import { useMemo, useRef, useState } from 'react'
import { Trash2, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { PLAYGROUND_FILTERS, PLAYGROUND_SLASH, takeLine } from '../../domain/playground.js'
import { useLayer } from '../../lib/layers.js'
import { Button, Modal } from '../ui/index.js'
import Room from '../room/Room.jsx'

/*
 * ============================================================================
 * PLAYGROUND — the War Room without an incident
 * ============================================================================
 *
 * The same screen as the War Room of an incident (components/room/Room.jsx),
 * on the whole space next to the rail: a stream, a line to write in with the
 * same completion, hints and history, the same inspector, the same question
 * before a command that changes something outside. What differs is what has
 * no meaning without an incident: `/assign` and `/close`, the steps of
 * playbooks, the mark of evidence. A reputation command adds no indicator to
 * anything, and a command that needs an incident fails and says so.
 *
 * The history is each person's own and is kept until they clear it.
 */

/**
 * @param {{ onClose: () => void }} props
 */
export default function PlaygroundPage({ onClose }) {
  const { can } = useAuth()
  const { showToast } = useToast()
  const [clearing, setClearing] = useState(null) // the reload to call once the history is cleared
  // A command sent here to be tried ("Try it" on a connector): its line is there to complete.
  const [firstLine] = useState(takeLine)

  // The shortcuts of what is under the page stand down; Escape is left to what is open inside it.
  const ref = useRef(null)
  useLayer(ref, { open: true, onClose: () => {}, trap: false, page: true })

  const source = useMemo(
    () => ({
      id: 'playground',
      label: 'Playground',
      base: '/playground',
      filters: PLAYGROUND_FILTERS,
      slash: PLAYGROUND_SLASH,
      canWrite: true,
      canRun: can('automation.run'),
      canMark: false,
      firstLine,
      placeholder: 'Write ! for a command, or a note to yourself',
      empty:
        'Nothing here yet. Run a command below: !ip 203.0.113.7, or ! and the name of a command of a connector. ' +
        'Nothing typed here touches an incident.',
      className: 'min-h-0 flex-1',
      actions: (reload) => (
        <Button variant="ghost" size="xs" icon={Trash2} onClick={() => setClearing(() => reload)}>
          Clear the history
        </Button>
      ),
    }),
    [can, firstLine],
  )

  const clear = async () => {
    const reload = clearing
    setClearing(null)
    try {
      await api.del('/playground')
      await reload?.()
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  return (
    <section
      ref={ref}
      aria-label="Playground"
      tabIndex={-1}
      className="flex min-w-0 flex-1 flex-col bg-canvas outline-none"
    >
      <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel px-6">
        <div className="flex min-w-0 items-baseline gap-3">
          <h1 className="text-sm font-semibold text-fg">Playground</h1>
          <p className="truncate text-xs text-fg-muted">
            Commands outside any incident. The history is yours alone, until you clear it.
          </p>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close the playground"
          title="Close the playground"
          className="p-1.5 text-fg-muted transition-colors hover:bg-canvas hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      </header>
      <Room source={source} />
      <Modal
        open={clearing !== null}
        onClose={() => setClearing(null)}
        title="Clear the history?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setClearing(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={clear}>
              Clear
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          Everything in your Playground is forgotten. The runs behind the commands stay in the list of runs.
        </p>
      </Modal>
    </section>
  )
}
