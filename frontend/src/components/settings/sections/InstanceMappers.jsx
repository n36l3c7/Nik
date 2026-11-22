import { useCallback, useEffect, useMemo, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import {
  ANY_TYPE,
  cellText,
  extraRows,
  fieldsOfSample,
  incomingRows,
  incomingRules,
  mapperKey,
  outgoingRows,
  outgoingRules,
  parseSample,
} from '../../../domain/mappers.js'
import { Badge, Button, Wait } from '../../ui/index.js'
import InstanceSample from './InstanceSample.jsx'
import { Expression, INPUT, LABEL, SELECT, TD, TH } from './mapperParts.jsx'

/*
 * The mappers, in the form of an instance: how what the connector's product
 * calls things becomes Nik's fields and context (incoming), and back
 * (outgoing). For a direction and a type of incident: a table with one row
 * for each field (those the type needs first, then those that are mapped,
 * then the rest folded away), the expression that gives its value, and what
 * that value is on a sample.
 *
 * A mapper belongs to the connector: every instance of it uses the same ones,
 * and the form says so. What is edited here is a draft held by the form of
 * the instance (InstancePane.jsx) and saved by its one "Save"; a mapper of
 * another type or direction that was changed is kept until then. Nothing is
 * written to an incident here: the sample is tried on the server and shown.
 */

/**
 * @param {{
 *   connector: object,
 *   instance: object,
 *   drafts: Record<string, { rows: object[], extras: object[], outRows: object[] }>,  // by mapperKey
 *   onDrafts: (drafts: object) => void,
 *   pasted: string,
 *   onPasted: (text: string) => void,
 * }} props
 */
export default function InstanceMappers({ connector, instance, drafts, onDrafts, pasted, onPasted }) {
  const { types } = useFields()
  const [direction, setDirection] = useState('incoming')
  const [typeId, setTypeId] = useState(ANY_TYPE)
  const [targets, setTargets] = useState(null) // { type, fields, context }: Nik's side for the type
  const [saved, setSaved] = useState(null)
  const [showRest, setShowRest] = useState(false)
  const [incidentId, setIncidentId] = useState('')
  const [tried, setTried] = useState(null)
  const [error, setError] = useState(null)
  const connectorId = connector.id

  const sample = useMemo(() => parseSample(pasted), [pasted])
  const itemFields = useMemo(() => {
    const named = connector?.schema?.incoming ?? []
    return named.length ? named : fieldsOfSample(sample.item)
  }, [connector, sample.item])

  // The saved mappers of this connector, and Nik's side for the type.
  const load = useCallback(async () => {
    try {
      const [found, sides] = await Promise.all([
        api.get(`/mappers?connector=${encodeURIComponent(connectorId)}`),
        api.get(`/mappers/targets?type=${encodeURIComponent(typeId)}`),
      ])
      setSaved(found.mappers)
      setTargets({ ...sides, type: typeId })
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [connectorId, typeId])
  useEffect(() => {
    load()
  }, [load])

  const ready = saved !== null && targets?.type === typeId
  const mapper = (saved ?? []).find((item) => item.direction === direction && item.incidentType === typeId) ?? null
  // What the tables show: the draft of this direction and type when it was changed, else what is saved.
  const key = mapperKey(direction, typeId)
  const stored = useMemo(() => {
    const rules = mapper?.rules ?? []
    return {
      rows: incomingRows(targets, direction === 'incoming' ? rules : []),
      extras: extraRows(targets, direction === 'incoming' ? rules : []),
      outRows: outgoingRows(connector?.schema, direction === 'outgoing' ? rules : []),
    }
  }, [mapper, targets, direction, connector])
  const draft = drafts[key] ?? null
  const { rows, extras, outRows } = draft ?? stored
  const edit = (patch) => onDrafts({ ...drafts, [key]: { rows, extras, outRows, ...patch } })
  const changeRow = (name, patch) => edit({ rows: rows.map((row) => (row.name === name ? { ...row, ...patch } : row)) })
  const setExtras = (next) => edit({ extras: next })
  const setOutRows = (next) => edit({ outRows: next })
  const choose = (change) => {
    setTried(null)
    change()
  }

  const rules = direction === 'incoming' ? incomingRules(rows, extras) : outgoingRules(outRows)
  const body = { connectorId, direction, incidentType: typeId, rules }
  const tryIt = async () => {
    setError(null)
    try {
      setTried(
        await api.post(
          '/mappers/try',
          direction === 'incoming' ? { ...body, item: sample.item } : { ...body, incidentId: incidentId.trim() },
        ),
      )
    } catch (failure) {
      setTried(null)
      setError(failure.message)
    }
  }

  const shown = rows.filter((row) => showRest || row.group !== 'rest' || row.from.trim())
  const hidden = rows.length - shown.length
  const label = direction === 'incoming' ? 'Mapper (incoming)' : 'Mapper (outgoing)'

  return (
    <section aria-label={label} className="flex flex-col gap-4 text-sm">
      <p className="max-w-3xl text-fg-muted">
        How what {connector.name} calls things becomes Nik&apos;s fields and context, and back. A mapper is for every
        type of incident, or for one type alone; a value the product does not send writes nothing.{' '}
        <strong className="font-medium text-fg">Shared by every instance of {connector.name}</strong>: what is changed
        here changes for all of them.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div role="group" aria-label="Direction" className="flex border border-line">
          {[
            { id: 'incoming', label: 'Incoming' },
            { id: 'outgoing', label: 'Outgoing' },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={direction === item.id}
              onClick={() => choose(() => setDirection(item.id))}
              className={[
                'h-8 px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                direction === item.id ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-raised hover:text-fg',
              ].join(' ')}
            >
              {item.label}
            </button>
          ))}
        </div>
        <label className="flex flex-col gap-1">
          <span className={LABEL}>Type of incident</span>
          <select
            aria-label="Type of incident"
            value={typeId}
            onChange={(event) => choose(() => setTypeId(event.target.value))}
            className={SELECT}
          >
            <option value={ANY_TYPE}>Every type</option>
            {types.map((type) => (
              <option key={type.id} value={type.id}>
                {type.name}
              </option>
            ))}
          </select>
        </label>
        {draft ? (
          <Badge color="amber">changed: Save keeps it</Badge>
        ) : mapper ? (
          <Badge color={mapper.builtin ? 'cyan' : 'emerald'}>
            {mapper.builtin ? 'shipped with the connector' : 'saved'}
          </Badge>
        ) : (
          <Badge color="slate">
            {typeId === ANY_TYPE ? 'no mapper yet' : 'none of its own: the one for every type applies'}
          </Badge>
        )}
      </div>

      {direction === 'incoming' ? (
        <InstanceSample instance={instance} pasted={pasted} onPasted={onPasted} problem={sample.problem} />
      ) : (
        <label className="flex max-w-md flex-col gap-1">
          <span className={LABEL}>An incident to try it on (its id)</span>
          <input
            type="text"
            aria-label="The id of an incident to try the mapper on"
            value={incidentId}
            spellCheck={false}
            onChange={(event) => setIncidentId(event.target.value)}
            className={`${INPUT} font-mono text-xs`}
          />
        </label>
      )}

      {!ready && !error ? (
        <Wait>Loading the mapper…</Wait>
      ) : (
        <div className="overflow-x-auto border border-line">
          {direction === 'incoming' ? (
            <table className="w-full min-w-[760px] border-collapse text-left text-sm">
              <caption className="sr-only">Rules of the incoming mapper</caption>
              <thead className="bg-panel font-mono text-xs text-fg-muted">
                <tr>
                  <th scope="col" className={TH}>
                    Field of Nik
                  </th>
                  <th scope="col" className={TH}>
                    Its value
                  </th>
                  <th scope="col" className={TH}>
                    On the sample
                  </th>
                  <th scope="col" className={TH}>
                    Wins over edits
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((row) => (
                  <tr key={row.name}>
                    <th scope="row" className={`${TD} font-normal`}>
                      {row.label}
                      {row.required && <span className="ml-1 text-high-fg">needed</span>}
                      <span className="block font-mono text-[11px] text-fg-subtle">{row.name}</span>
                    </th>
                    <td className={`${TD} w-[45%]`}>
                      <Expression
                        label={`${row.label}: its value`}
                        value={row.from}
                        fields={itemFields}
                        onChange={(from) => changeRow(row.name, { from })}
                      />
                    </td>
                    <td className={`${TD} break-all font-mono text-xs text-fg`}>
                      {cellText(tried?.fields?.[row.name])}
                    </td>
                    <td className={TD}>
                      <input
                        type="checkbox"
                        aria-label={`${row.label}: wins over what a person set`}
                        checked={row.authoritative}
                        disabled={!row.from.trim()}
                        onChange={(event) => changeRow(row.name, { authoritative: event.target.checked })}
                        className="h-4 w-4 accent-accent"
                      />
                    </td>
                  </tr>
                ))}
                {extras.map((extra, index) => (
                  <tr key={`extra-${index}`}>
                    <td className={TD}>
                      <input
                        type="text"
                        aria-label={`Context path ${index + 1}`}
                        value={extra.to}
                        spellCheck={false}
                        placeholder="Alert(val.ID == obj.ID)"
                        list="mapper-context-paths"
                        onChange={(event) =>
                          setExtras(
                            extras.map((item, at) => (at === index ? { ...item, to: event.target.value } : item)),
                          )
                        }
                        className={`${INPUT} font-mono text-xs`}
                      />
                    </td>
                    <td className={TD}>
                      <Expression
                        label={`Context path ${index + 1}: its value`}
                        value={extra.from}
                        fields={itemFields}
                        placeholder='{"ID": "{{ item.id }}"}'
                        onChange={(from) =>
                          setExtras(extras.map((item, at) => (at === index ? { ...item, from } : item)))
                        }
                      />
                    </td>
                    <td className={`${TD} break-all font-mono text-xs text-fg`}>
                      {cellText(tried?.context?.find((write) => write.path === extra.to)?.value)}
                    </td>
                    <td className={TD}>
                      <Button
                        variant="ghost"
                        size="xs"
                        icon={X}
                        aria-label={`Remove context path ${index + 1}`}
                        onClick={() => setExtras(extras.filter((_, at) => at !== index))}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="w-full min-w-[760px] border-collapse text-left text-sm">
              <caption className="sr-only">Rules of the outgoing mapper</caption>
              <thead className="bg-panel font-mono text-xs text-fg-muted">
                <tr>
                  <th scope="col" className={TH}>
                    Name of the product
                  </th>
                  <th scope="col" className={TH}>
                    Its value
                  </th>
                  <th scope="col" className={TH}>
                    For the incident
                  </th>
                  <th scope="col" className={TH}>
                    <span className="sr-only">Remove</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {outRows.map((row, index) => (
                  <tr key={index}>
                    <td className={TD}>
                      {row.known ? (
                        <span className="font-mono text-xs">{row.to}</span>
                      ) : (
                        <input
                          type="text"
                          aria-label={`Name ${index + 1}`}
                          value={row.to}
                          spellCheck={false}
                          onChange={(event) =>
                            setOutRows(
                              outRows.map((item, at) => (at === index ? { ...item, to: event.target.value } : item)),
                            )
                          }
                          className={`${INPUT} font-mono text-xs`}
                        />
                      )}
                    </td>
                    <td className={`${TD} w-[50%]`}>
                      <Expression
                        label={`${row.to || `Name ${index + 1}`}: its value`}
                        value={row.from}
                        root="incident"
                        fields={(targets?.fields ?? []).map((field) => ({ name: field.name }))}
                        placeholder="{{ incident.name }}"
                        onChange={(from) =>
                          setOutRows(outRows.map((item, at) => (at === index ? { ...item, from } : item)))
                        }
                      />
                    </td>
                    <td className={`${TD} break-all font-mono text-xs text-fg`}>{cellText(tried?.sent?.[row.to])}</td>
                    <td className={TD}>
                      {!row.known && (
                        <Button
                          variant="ghost"
                          size="xs"
                          icon={X}
                          aria-label={`Remove name ${index + 1}`}
                          onClick={() => setOutRows(outRows.filter((_, at) => at !== index))}
                        />
                      )}
                    </td>
                  </tr>
                ))}
                {outRows.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-2 py-3 text-sm text-fg-muted">
                      The connector names no field it takes: add the names it wants below.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      )}
      <datalist id="mapper-context-paths">
        {(targets?.context ?? []).map((item) => (
          <option key={item.entity} value={item.path} />
        ))}
        {(connector?.extFields ?? []).map((item) => (
          <option key={item.name} value={`ext.${connectorId}.${item.name}`} />
        ))}
      </datalist>

      <div className="flex flex-wrap items-center gap-2">
        {direction === 'incoming' && hidden > 0 && (
          <Button variant="ghost" size="sm" onClick={() => setShowRest(true)}>
            Show the {hidden} other fields
          </Button>
        )}
        {direction === 'incoming' ? (
          <Button
            variant="secondary"
            size="sm"
            icon={Plus}
            disabled={!ready}
            onClick={() => setExtras([...extras, { to: '', from: '' }])}
          >
            Add a context path
          </Button>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            icon={Plus}
            disabled={!ready}
            onClick={() => setOutRows([...outRows, { to: '', from: '', known: false }])}
          >
            Add a name
          </Button>
        )}
        <Button
          variant="secondary"
          size="sm"
          disabled={!ready || (direction === 'incoming' ? !sample.item : !incidentId.trim())}
          onClick={tryIt}
        >
          Try on the sample
        </Button>
        {draft && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              const { [key]: _dropped, ...rest } = drafts
              setTried(null)
              onDrafts(rest)
            }}
          >
            Put back what is saved
          </Button>
        )}
      </div>

      {tried && direction === 'incoming' && (tried.problems.length > 0 || tried.missing.length > 0) && (
        <div
          role="status"
          className="flex flex-col gap-1 border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg"
        >
          {tried.missing.length > 0 && <p>Needed by the type and not given: {tried.missing.join(', ')}.</p>}
          {tried.problems.map((problem, index) => (
            <p key={index}>{problem}</p>
          ))}
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
    </section>
  )
}
