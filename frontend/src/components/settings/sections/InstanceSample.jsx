import { useState } from 'react'
import { api } from '../../../services/api.js'
import { Button } from '../../ui/index.js'

/*
 * A sample for the classifier and the mappers of an instance: one item as the
 * product sends it, pasted or taken from what the instance fetched last. The
 * form of the instance holds it, so that the classifier and the mapper are
 * tried on the same one.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   instance: object,
 *   pasted: string,
 *   onPasted: (text: string) => void,
 *   problem?: string | null,       // why what is pasted is not an item
 * }} props
 */
export default function InstanceSample({ instance, pasted, onPasted, problem = null }) {
  const [said, setSaid] = useState(null)
  const useLast = async () => {
    setSaid(null)
    try {
      const found = await api.get(`/fetch/${encodeURIComponent(instance.id)}/sample`)
      if (found.item) onPasted(JSON.stringify(found.item, null, 2))
      else setSaid(`${instance.name} has fetched nothing yet`)
    } catch (failure) {
      setSaid(failure.message)
    }
  }
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-fg-muted">A sample: one item as the product sends it (JSON)</span>
      <textarea
        aria-label="A sample item, as JSON"
        value={pasted}
        rows={5}
        spellCheck={false}
        placeholder='{"id": "T-77", "threatInfo": {"threatName": "Emotet.dll"}}'
        onChange={(event) => onPasted(event.target.value)}
        className={INPUT}
      />
      {problem && <span className="text-xs text-high-fg">{problem}</span>}
      {instance.fetch && (
        <span className="flex flex-wrap items-center gap-2">
          <Button variant="ghost" size="xs" onClick={useLast}>
            Use the last item it fetched
          </Button>
          {said && (
            <span role="status" className="text-xs text-fg-muted">
              {said}
            </span>
          )}
        </span>
      )}
    </label>
  )
}
