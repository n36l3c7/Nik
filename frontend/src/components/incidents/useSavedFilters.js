import { useCallback, useEffect, useState } from 'react'
import { api } from '../../services/api.js'

/*
 * The saved filters of a list, read from the server (GET /api/filters) and
 * read again after every change: one's own, those shared with everyone, and
 * the id of the one the list opens with.
 *
 * Every change returns what the server answered and throws what it refused,
 * so the dialog that asked can say why.
 */

/** @param {string} entity  the list the filters are for ('incidents') */
export function useSavedFilters(entity = 'incidents') {
  const [state, setState] = useState({ filters: [], defaultId: null, ready: false })

  const reload = useCallback(async () => {
    try {
      const found = await api.get(`/filters?entity=${encodeURIComponent(entity)}`)
      setState({ filters: found.filters ?? [], defaultId: found.default ?? null, ready: true })
    } catch {
      // The list still works without them: it opens with no filter.
      setState((current) => ({ ...current, ready: true }))
    }
  }, [entity])

  useEffect(() => {
    reload()
  }, [reload])

  const then = useCallback(
    async (request) => {
      try {
        return await request
      } finally {
        await reload()
      }
    },
    [reload],
  )

  const create = useCallback((body) => then(api.post('/filters', { entity, ...body })), [entity, then])
  const update = useCallback((id, body) => then(api.put(`/filters/${encodeURIComponent(id)}`, body)), [then])
  const remove = useCallback((id) => then(api.del(`/filters/${encodeURIComponent(id)}`)), [then])
  const share = useCallback(
    (id, shared) => then(api.put(`/filters/${encodeURIComponent(id)}/sharing`, { shared })),
    [then],
  )
  /** Choose the filter the list opens with; `null` for none. */
  const setDefault = useCallback(
    (id) =>
      then(
        id
          ? api.put(`/filters/default/${encodeURIComponent(entity)}`, { filterId: id })
          : api.del(`/filters/default/${encodeURIComponent(entity)}`),
      ),
    [entity, then],
  )

  return { ...state, reload, create, update, remove, share, setDefault }
}
