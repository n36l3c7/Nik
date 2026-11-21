import { useEffect, useState } from 'react'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { choiceValue, instanceChoice } from '../../../domain/indicatorsFound.js'
import { Select } from '../../ui/index.js'

/**
 * Whether the incidents one instance of a connector brings in are read for indicators: as the
 * setting says (Settings, Indicators found), always, or never. It keeps itself: it reads what
 * the instance says and saves a choice at once. It is drawn in the Fetch part of the form of an
 * instance, which is narrow: the choice goes under its name when the two do not fit on a line.
 *
 * @param {{ connectionId: string, name?: string, onChanged?: () => void }} props
 */
export default function FindIndicatorsSwitch({ connectionId, name = '', onChanged = undefined }) {
  const { showToast } = useToast()
  const [found, setFound] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let alive = true
    setFound(null)
    api
      .get(`/iocs/found/instances/${encodeURIComponent(connectionId)}`)
      .then((answer) => alive && setFound(answer))
      .catch(() => alive && setFound(null))
    return () => {
      alive = false
    }
  }, [connectionId])

  if (!found) return null
  const choose = async (choice) => {
    setBusy(true)
    try {
      const body = { enabled: choiceValue(choice) }
      setFound(await api.put(`/iocs/found/instances/${encodeURIComponent(connectionId)}`, body))
      onChanged?.()
    } catch (failure) {
      showToast({ message: failure.message })
    }
    setBusy(false)
  }
  const options = [
    { value: 'setting', label: `As the setting says (${found.setting ? 'read' : 'not read'})` },
    { value: 'on', label: 'Read' },
    { value: 'off', label: 'Not read' },
  ]
  return (
    <Select
      label={`Indicators in the incidents of ${name || 'this instance'}`}
      value={instanceChoice(found.enabled)}
      onChange={choose}
      options={options}
      disabled={busy}
      className="flex-wrap"
    />
  )
}
