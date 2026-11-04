/*
 * RFC 7396 JSON Merge Patch generation.
 *
 * `createMergePatch(prev, next)` returns the smallest merge patch that turns
 * `prev` into `next`: changed members are listed, removed members are `null`,
 * nested objects are diffed recursively and anything else (arrays included)
 * is sent whole. Subtrees that are the SAME reference are skipped without
 * being walked, which makes the diff cheap for immutable React state.
 *
 * Limitation inherent to the format: a merge patch cannot store an explicit
 * `null` — a member set to `null` is removed on the server. Incident documents
 * are normalized on load, so a removed member reads back as its default.
 */

export const MERGE_PATCH_CONTENT_TYPE = 'application/merge-patch+json'

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/**
 * @param {object} prev  Previous version of the document.
 * @param {object} next  New version of the document.
 * @returns {object} The merge patch (empty object when nothing changed).
 */
export function createMergePatch(prev, next) {
  const patch = {}
  for (const key of Object.keys(prev)) {
    if (next[key] === undefined) patch[key] = null
  }
  for (const [key, value] of Object.entries(next)) {
    if (value === undefined || Object.is(prev[key], value)) continue
    if (isPlainObject(prev[key]) && isPlainObject(value)) {
      const nested = createMergePatch(prev[key], value)
      if (Object.keys(nested).length > 0) patch[key] = nested
    } else {
      patch[key] = value
    }
  }
  return patch
}
