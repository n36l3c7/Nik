/** Generate a unique id (for incidents and imported rows). */
export function generateId() {
  return (
    crypto.randomUUID?.() ??
    `id-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
  )
}
