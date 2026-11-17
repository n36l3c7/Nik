import { useCallback, useEffect, useMemo, useState } from 'react'
import { Plus, Save, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import {
  ANY_TYPE,
  OPERATORS,
  cellText,
  classifierRows,
  classifierRules,
  conditionText,
  extraRows,
  fieldsOfSample,
  incomingRows,
  incomingRules,
  isUnary,
  outgoingRows,
  outgoingRules,
  parseSample,
  withField,
} from '../../../domain/mappers.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * Automation → Classifiers and mappers (who manages connectors).
 *
 * How what a connector's product calls things becomes Nik's, and back. For a
 * connector, a direction and a type of incident: a table with one row for
 * each field (those the type needs first, then those that are mapped, then
 * the rest folded away), the expression that gives its value, and what that
 * value is on a sample. Under it, for a connection that fetches, the small
 * table of its classifier: which type of incident an item becomes.
 *
 * Nothing is written to an incident here: the sample is tried on the server
 * and shown.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const SELECT = `${INPUT} cursor-pointer`
const LABEL = 'text-xs font-medium text-fg-muted'
const TH = 'border-b border-line px-2 py-1.5 font-normal'
const TD = 'border-b border-line-soft px-2 py-1 align-top'

/** An expression with, beside it, the fields of the product to put into it. */
function Expression({ label, value, onChange, fields, root = 'item', placeholder = '' }) {
  return (
    <div className="flex gap-1">
      <input
        type="text"
        aria-label={label}
        value={value}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={`${INPUT} font-mono text-xs`}
      />
      {fields.length > 0 && (
        <select
          aria-label={`${label}: put a field in`}
          value=""
          onChange={(event) => event.target.value && onChange(withField(value, event.target.value, root))}
          className="w-9 shrink-0 cursor-pointer border border-line bg-canvas px-1 text-sm text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="">+</option>
          {fields.map((field) => (
            <option key={field.name} value={field.name}>
              {field.name}
            </option>
          ))}
        </select>
      )}
    </div>
  )
}

/** The classifier of one connection: an ordered table of condition → type. */
function Classifier({ connection, types, sample, itemFields }) {
  const [rows, setRows] = useState([])
  const [fallback, setFallback] = useState('')
  const [said, setSaid] = useState(null)
  const [error, setError] = useState(null)
  const [becomes, setBecomes] = useState(undefined)

  useEffect(() => {
    let cancelled = false
    api.get(`/classifiers/${encodeURIComponent(connection.id)}`).then(
      (found) => {
        if (cancelled) return
        setRows(classifierRows(found.rules))
        setFallback(found.defaultType ?? '')
      },
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [connection.id])

  const body = { rules: classifierRules(rows), defaultType: fallback || null }
  const change = (index, patch) => {
    setSaid(null)
    setRows(rows.map((row, at) => (at === index ? { ...row, ...patch } : row)))
  }
  const run = async (request, done) => {
    setError(null)
    setSaid(null)
    try {
      await request()
      setSaid(done)
    } catch (failure) {
      setError(failure.message)
    }
  }
  const tryIt = () =>
    run(async () => {
      const found = await api.post('/classifiers/try', { ...body, item: sample })
      setBecomes(found.type)
    }, null)
  const typeName = (id) => types.find((type) => type.id === id)?.name ?? id

  return (
    <section aria-label={`Classifier of ${connection.name}`} className="flex flex-col gap-2 border border-line p-3">
      <h4 className="text-sm font-semibold text-fg">
        Classifier of {connection.name}
        <span className="ml-2 font-normal text-fg-muted">which type of incident an item becomes</span>
      </h4>
      <div className="overflow-x-auto border border-line">
        <table className="w-full min-w-[640px] border-collapse text-left text-sm">
          <caption className="sr-only">Rules of the classifier of {connection.name}</caption>
          <thead className="bg-panel font-mono text-xs text-fg-muted">
            <tr>
              <th scope="col" className={TH}>
                When
              </th>
              <th scope="col" className={TH}>
                Compares
              </th>
              <th scope="col" className={TH}>
                With
              </th>
              <th scope="col" className={TH}>
                It becomes
              </th>
              <th scope="col" className={TH}>
                <span className="sr-only">Remove</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, index) => (
              <tr key={index}>
                {row.kept ? (
                  <td colSpan={3} className={`${TD} font-mono text-xs text-fg-muted`}>
                    {conditionText(row.kept)}
                  </td>
                ) : (
                  <>
                    <td className={TD}>
                      <Expression
                        label={`Rule ${index + 1}: what to compare`}
                        value={row.left}
                        fields={itemFields}
                        placeholder="{{ item.type }}"
                        onChange={(left) => change(index, { left })}
                      />
                    </td>
                    <td className={TD}>
                      <select
                        aria-label={`Rule ${index + 1}: how`}
                        value={row.op}
                        onChange={(event) => change(index, { op: event.target.value })}
                        className={SELECT}
                      >
                        {OPERATORS.map((operator) => (
                          <option key={operator.id} value={operator.id}>
                            {operator.label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className={TD}>
                      {!isUnary(row.op) && (
                        <input
                          type="text"
                          aria-label={`Rule ${index + 1}: with what`}
                          value={row.right}
                          onChange={(event) => change(index, { right: event.target.value })}
                          className={`${INPUT} font-mono text-xs`}
                        />
                      )}
                    </td>
                  </>
                )}
                <td className={TD}>
                  <select
                    aria-label={`Rule ${index + 1}: the type it becomes`}
                    value={row.type ?? ''}
                    onChange={(event) => change(index, { type: event.target.value })}
                    className={SELECT}
                  >
                    <option value="">(choose a type)</option>
                    {types.map((type) => (
                      <option key={type.id} value={type.id}>
                        {type.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td className={TD}>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={X}
                    aria-label={`Remove rule ${index + 1}`}
                    onClick={() => setRows(rows.filter((_, at) => at !== index))}
                  />
                </td>
              </tr>
            ))}
            <tr>
              <td colSpan={3} className={`${TD} text-sm text-fg-muted`}>
                Otherwise
              </td>
              <td className={TD}>
                <select
                  aria-label="The type when no rule holds"
                  value={fallback}
                  onChange={(event) => {
                    setSaid(null)
                    setFallback(event.target.value)
                  }}
                  className={SELECT}
                >
                  <option value="">Unclassified</option>
                  {types.map((type) => (
                    <option key={type.id} value={type.id}>
                      {type.name}
                    </option>
                  ))}
                </select>
              </td>
              <td className={TD} />
            </tr>
          </tbody>
        </table>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="secondary"
          size="sm"
          icon={Plus}
          onClick={() => setRows([...rows, { left: '', op: 'eq', right: '', type: '', kept: null }])}
        >
          Add a rule
        </Button>
        <Button
          size="sm"
          icon={Save}
          onClick={() =>
            run(() => api.put(`/classifiers/${encodeURIComponent(connection.id)}`, body), 'The classifier is saved.')
          }
        >
          Save the classifier
        </Button>
        <Button variant="secondary" size="sm" disabled={!sample} onClick={tryIt}>
          Try on the sample
        </Button>
        {becomes !== undefined && (
          <span role="status" className="text-sm text-fg">
            The sample becomes: <strong>{becomes ? typeName(becomes) : 'Unclassified'}</strong>
          </span>
        )}
      </div>
      {(error || said) && (
        <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
          {error || said}
        </p>
      )}
    </section>
  )
}

export default function MappersSection() {
  const { types } = useFields()
  const [connectors, setConnectors] = useState(null)
  const [connections, setConnections] = useState([])
  const [connectorId, setConnectorId] = useState('')
  const [direction, setDirection] = useState('incoming')
  const [typeId, setTypeId] = useState(ANY_TYPE)
  const [targets, setTargets] = useState(null)
  const [saved, setSaved] = useState([])
  const [rows, setRows] = useState([])
  const [extras, setExtras] = useState([])
  const [outRows, setOutRows] = useState([])
  const [showRest, setShowRest] = useState(false)
  const [pasted, setPasted] = useState('')
  const [incidentId, setIncidentId] = useState('')
  const [tried, setTried] = useState(null)
  const [error, setError] = useState(null)
  const [said, setSaid] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.all([api.get('/automation/connectors'), api.get('/automation/connections')]).then(
      ([first, second]) => {
        if (cancelled) return
        setConnectors(first.connectors)
        setConnections(second.connections)
        setConnectorId((current) => current || first.connectors[0]?.id || '')
      },
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [])

  const connector = connectors?.find((item) => item.id === connectorId) ?? null
  const sample = useMemo(() => parseSample(pasted), [pasted])
  const itemFields = useMemo(() => {
    const named = connector?.schema?.incoming ?? []
    return named.length ? named : fieldsOfSample(sample.item)
  }, [connector, sample.item])

  // The saved mapper of this connector, direction and type, and Nik's side for the type.
  const load = useCallback(async () => {
    if (!connectorId) return
    try {
      const [found, sides] = await Promise.all([
        api.get(`/mappers?connector=${encodeURIComponent(connectorId)}`),
        api.get(`/mappers/targets?type=${encodeURIComponent(typeId)}`),
      ])
      setSaved(found.mappers)
      setTargets(sides)
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [connectorId, typeId])
  useEffect(() => {
    load()
  }, [load])

  const mapper = saved.find((item) => item.direction === direction && item.incidentType === typeId) ?? null
  useEffect(() => {
    const rules = mapper?.rules ?? []
    setRows(incomingRows(targets, direction === 'incoming' ? rules : []))
    setExtras(extraRows(targets, direction === 'incoming' ? rules : []))
    setOutRows(outgoingRows(connector?.schema, direction === 'outgoing' ? rules : []))
    setTried(null)
  }, [mapper, targets, direction, connector])
  // "Saved" is said of the mapper that was saved, until another is chosen or a rule is changed.
  useEffect(() => {
    setSaid(null)
  }, [connectorId, direction, typeId])

  const rules = direction === 'incoming' ? incomingRules(rows, extras) : outgoingRules(outRows)
  const changeRow = (name, patch) => {
    setSaid(null)
    setRows(rows.map((row) => (row.name === name ? { ...row, ...patch } : row)))
  }
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
  const save = async () => {
    setError(null)
    try {
      await api.put('/mappers', body)
      await load()
      setSaid('The mapper is saved.')
    } catch (failure) {
      setError(failure.message)
    }
  }

  if (connectors === null && !error) {
    return (
      <p role="status" className="font-mono text-sm text-fg-muted">
        Loading the connectors…
      </p>
    )
  }
  if (connectors?.length === 0) {
    return (
      <p className="text-sm text-fg-muted">
        There is no connector yet: add one in <em>Connectors</em>, then say here how its names become Nik&apos;s.
      </p>
    )
  }
  const shown = rows.filter((row) => showRest || row.group !== 'rest' || row.from.trim())
  const hidden = rows.length - shown.length
  const fetching = connections.filter((connection) => connection.connector === connectorId)

  return (
    <div className="flex max-w-6xl flex-col gap-5">
      <p className="max-w-3xl text-sm text-fg-muted">
        How what a connector&apos;s product calls things becomes Nik&apos;s fields and context, and back. A mapper is
        for every type of incident, or for one type alone; a value the product does not send writes nothing.
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1">
          <span className={LABEL}>Connector</span>
          <select
            aria-label="Connector"
            value={connectorId}
            onChange={(event) => setConnectorId(event.target.value)}
            className={SELECT}
          >
            {(connectors ?? []).map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <div role="group" aria-label="Direction" className="flex border border-line">
          {[
            { id: 'incoming', label: 'Incoming' },
            { id: 'outgoing', label: 'Outgoing' },
          ].map((item) => (
            <button
              key={item.id}
              type="button"
              aria-pressed={direction === item.id}
              onClick={() => setDirection(item.id)}
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
            onChange={(event) => setTypeId(event.target.value)}
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
        {mapper ? (
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
        <label className="flex flex-col gap-1">
          <span className={LABEL}>A sample: one item as the product sends it (JSON)</span>
          <textarea
            aria-label="A sample item, as JSON"
            value={pasted}
            rows={5}
            spellCheck={false}
            placeholder='{"id": "T-77", "threatInfo": {"threatName": "Emotet.dll"}}'
            onChange={(event) => setPasted(event.target.value)}
            className={`${INPUT} font-mono text-xs`}
          />
          {sample.problem && <span className="text-xs text-high-fg">{sample.problem}</span>}
        </label>
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
                  <td className={`${TD} break-all font-mono text-xs text-fg`}>{cellText(tried?.fields?.[row.name])}</td>
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
                        setExtras(extras.map((item, at) => (at === index ? { ...item, to: event.target.value } : item)))
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
            onClick={() => setExtras([...extras, { to: '', from: '' }])}
          >
            Add a context path
          </Button>
        ) : (
          <Button
            variant="secondary"
            size="sm"
            icon={Plus}
            onClick={() => setOutRows([...outRows, { to: '', from: '', known: false }])}
          >
            Add a name
          </Button>
        )}
        <Button
          variant="secondary"
          size="sm"
          disabled={direction === 'incoming' ? !sample.item : !incidentId.trim()}
          onClick={tryIt}
        >
          Try on the sample
        </Button>
        <Button size="sm" icon={Save} onClick={save}>
          Save the mapper
        </Button>
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
      {(error || said) && (
        <p role={error ? 'alert' : 'status'} className={`text-sm ${error ? 'text-high-fg' : 'text-fg-muted'}`}>
          {error || said}
        </p>
      )}

      {direction === 'incoming' &&
        fetching.map((connection) => (
          <Classifier
            key={connection.id}
            connection={connection}
            types={types}
            sample={sample.item}
            itemFields={itemFields}
          />
        ))}
    </div>
  )
}
