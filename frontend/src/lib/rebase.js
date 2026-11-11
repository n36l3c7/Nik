/*
 * Three-way merge of JSON documents.
 *
 * `rebase(base, local, remote)` carries the changes made here (from `base` to
 * `local`) onto the version somebody else saved meanwhile (`remote`): what
 * only one side changed is kept from that side, objects are merged member by
 * member, and lists of things with an identity (an `id`, a `sha256`, a `key`:
 * notes, comments, references) are merged item by item, so a note added here
 * and one added there both survive. Where both sides changed the same value
 * and it cannot be merged, this side wins: it is what the analyst just did.
 *
 * Whatever is unchanged here is returned as the `remote` reference itself, so
 * the next diff against `remote` skips it without walking it.
 */

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Deep equality of JSON values; a member set to `undefined` counts as absent. */
export function isEqual(a, b) {
  if (Object.is(a, b)) return true
  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every((value, index) => isEqual(value, b[index]))
  }
  if (!isPlainObject(a) || !isPlainObject(b)) return false
  const keysA = Object.keys(a).filter((key) => a[key] !== undefined)
  const keysB = Object.keys(b).filter((key) => b[key] !== undefined)
  return keysA.length === keysB.length && keysA.every((key) => isEqual(a[key], b[key]))
}

const identityOf = (item) => (isPlainObject(item) ? (item.id ?? item.sha256 ?? item.key ?? null) : null)

/** The items by identity, or null when the list is not one of identified things. */
function indexed(list) {
  if (!Array.isArray(list)) return null
  const byIdentity = new Map()
  for (const item of list) {
    const identity = identityOf(item)
    if (identity === null || byIdentity.has(identity)) return null
    byIdentity.set(identity, item)
  }
  return byIdentity
}

function rebaseList(base, local, remote) {
  const merged = []
  for (const [identity, item] of remote) {
    if (local.has(identity)) merged.push(rebase(base.get(identity), local.get(identity), item))
    // Not here, and it was not in the common version: added there.
    else if (!base.has(identity)) merged.push(item)
  }
  for (const [identity, item] of local) {
    if (remote.has(identity)) continue
    // Added here; or removed there while it was edited here, and the edit is kept.
    if (!base.has(identity) || !isEqual(item, base.get(identity))) merged.push(item)
  }
  return merged
}

/**
 * @param {*} base    The version both sides started from.
 * @param {*} local   This side's version.
 * @param {*} remote  The version saved meanwhile.
 * @returns {*} `remote` with this side's changes on top.
 */
export function rebase(base, local, remote) {
  if (Object.is(local, base) || isEqual(local, remote) || isEqual(local, base)) return remote
  // Objects are always merged member by member, even when only this side
  // changed: the members left alone must come back as `remote`'s.
  if (isPlainObject(local) && isPlainObject(remote)) {
    const origin = isPlainObject(base) ? base : {}
    const merged = {}
    for (const key of new Set([...Object.keys(remote), ...Object.keys(local)])) {
      const value = rebase(origin[key], local[key], remote[key])
      if (value !== undefined) merged[key] = value
    }
    return merged
  }
  if (isEqual(remote, base)) return local
  const localItems = indexed(local)
  const remoteItems = indexed(remote)
  const baseItems = base === undefined ? new Map() : indexed(base)
  if (localItems && remoteItems && baseItems) return rebaseList(baseItems, localItems, remoteItems)
  return local
}
