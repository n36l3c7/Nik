import { useEffect, useState } from 'react'
import { api } from './api.js'

/*
 * The fields of the entities a query can be asked of (GET /api/query/schema),
 * fetched once per sign-in and shared by every query input. Without it an
 * input still works as plain text: it only loses colours for unknown fields,
 * the autocomplete and the builder's pickers.
 */

let pending = null

function load() {
  pending ??= api
    .get('/query/schema')
    .then((res) => new Map((res?.entities ?? []).map((entity) => [entity.entity, entity])))
    .catch(() => {
      pending = null // asked again by the next input
      return new Map()
    })
  return pending
}

/** Forget the schema (at sign-out: another account may query other entities). */
export function resetQuerySchema() {
  pending = null
}

/** The schema of an entity, or null while it loads or when the account may not query it. */
export function useQuerySchema(entity) {
  const [schema, setSchema] = useState(null)
  useEffect(() => {
    let cancelled = false
    load().then((entities) => {
      if (!cancelled) setSchema(entities.get(entity) ?? null)
    })
    return () => {
      cancelled = true
    }
  }, [entity])
  return schema
}
