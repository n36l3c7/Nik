import { useEffect, useMemo, useState } from 'react'
import { Plus, X } from 'lucide-react'
import { api } from '../../../services/api.js'
import { useFields } from '../../../context/FieldsContext.jsx'
import {
  OPERATORS,
  classifierBody,
  classifierRows,
  conditionText,
  fieldsOfSample,
  isUnary,
  parseSample,
} from '../../../domain/mappers.js'
import { Badge, Button } from '../../ui/index.js'
import InstanceSample from './InstanceSample.jsx'
import { Expression, INPUT, SELECT, TD, TH } from './mapperParts.jsx'

/*
 * The classifier of an instance: an ordered table of condition → type of
 * incident. The first rule that holds gives the type of a fetched item; when
 * none does, the type under "Otherwise".
 *
 * It is a part of the form of the instance (InstancePane.jsx), which holds
 * what is edited here as a draft and saves it with everything else: there is
 * one "Save". Trying the rules on a sample writes nothing.
 */

/**
 * @param {{
 *   connector: object,
 *   instance: object,
 *   draft: { rows: object[], fallback: string } | null,   // what was changed and is not saved yet
 *   onDraft: (draft: object) => void,
 *   pasted: string,
 *   onPasted: (text: string) => void,
 * }} props
 */
export default function InstanceClassifier({ connector, instance, draft, onDraft, pasted, onPasted }) {
  const { types } = useFields()
  const [loaded, setLoaded] = useState(null)
  const [error, setError] = useState(null)
  const [becomes, setBecomes] = useState(undefined)

  useEffect(() => {
    let cancelled = false
    api.get(`/classifiers/${encodeURIComponent(instance.id)}`).then(
      (found) =>
        !cancelled && setLoaded({ rows: classifierRows(found.rules), fallback: found.defaultType ?? '', found }),
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [instance.id])

  const sample = useMemo(() => parseSample(pasted), [pasted])
  const itemFields = useMemo(() => {
    const named = connector?.schema?.incoming ?? []
    return named.length ? named : fieldsOfSample(sample.item)
  }, [connector, sample.item])

  const rows = draft?.rows ?? loaded?.rows ?? []
  const fallback = draft?.fallback ?? loaded?.fallback ?? ''
  const edit = (patch) => {
    setBecomes(undefined)
    onDraft({ rows, fallback, ...patch })
  }
  const change = (index, patch) => edit({ rows: rows.map((row, at) => (at === index ? { ...row, ...patch } : row)) })
  const tryIt = async () => {
    setError(null)
    try {
      const found = await api.post('/classifiers/try', { ...classifierBody({ rows, fallback }), item: sample.item })
      setBecomes(found.type)
    } catch (failure) {
      setError(failure.message)
    }
  }
  const typeName = (id) => types.find((type) => type.id === id)?.name ?? id

  if (loaded === null && !error) {
    return (
      <p role="status" className="font-mono text-sm text-fg-muted">
        Loading the classifier…
      </p>
    )
  }

  return (
    <section aria-label={`Classifier of ${instance.name}`} className="flex flex-col gap-3 text-sm">
      <p className="flex max-w-3xl flex-wrap items-center gap-2 text-fg-muted">
        Which type of incident an item fetched by {instance.name} becomes: the first rule that holds gives it.
        {draft ? (
          <Badge color="amber">changed: Save keeps it</Badge>
        ) : loaded?.found?.updatedAt ? (
          <Badge color="emerald">saved</Badge>
        ) : (
          <Badge color="slate">no rule yet</Badge>
        )}
      </p>
      <div className="overflow-x-auto border border-line">
        <table className="w-full min-w-[640px] border-collapse text-left text-sm">
          <caption className="sr-only">Rules of the classifier of {instance.name}</caption>
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
                    onClick={() => edit({ rows: rows.filter((_, at) => at !== index) })}
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
                  onChange={(event) => edit({ fallback: event.target.value })}
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
          onClick={() => edit({ rows: [...rows, { left: '', op: 'eq', right: '', type: '', kept: null }] })}
        >
          Add a rule
        </Button>
        <Button variant="secondary" size="sm" disabled={!sample.item} onClick={tryIt}>
          Try on the sample
        </Button>
        {becomes !== undefined && (
          <span role="status" className="text-sm text-fg">
            The sample becomes: <strong>{becomes ? typeName(becomes) : 'Unclassified'}</strong>
          </span>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      <InstanceSample instance={instance} pasted={pasted} onPasted={onPasted} problem={sample.problem} />
    </section>
  )
}
