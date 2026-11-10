/**
 * Card — standard container of the Nik design system.
 *
 * Optional header (title + icon on the left, `actions` on the right),
 * body customizable with `bodyClassName`.
 */
export default function Card({
  title,
  icon: Icon = null,
  actions = null,
  children,
  className = '',
  bodyClassName = '',
}) {
  // The header is rendered only if there is at least a title, icon or actions
  const hasHeader = Boolean(title || Icon || actions)

  return (
    <section className={`border border-line bg-panel ${className}`}>
      {hasHeader && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-2.5">
          <div className="flex min-w-0 items-center gap-2">
            {Icon && <Icon className="h-4 w-4 shrink-0 text-accent" aria-hidden="true" />}
            {title && <h3 className="truncate text-sm font-semibold text-fg">{title}</h3>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={`p-4 ${bodyClassName}`}>{children}</div>
    </section>
  )
}
