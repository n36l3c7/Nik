/**
 * Card — standard container of the CSAP design system.
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
    <section
      className={[
        'rounded-xl border border-slate-200 bg-white',
        'dark:border-slate-800 dark:bg-slate-900',
        className,
      ].join(' ')}
    >
      {hasHeader && (
        <header className="flex items-center justify-between gap-3 border-b border-slate-200 px-5 py-3.5 dark:border-slate-800">
          <div className="flex min-w-0 items-center gap-2">
            {Icon && (
              <Icon
                className="h-4 w-4 shrink-0 text-cyan-600 dark:text-cyan-400"
                aria-hidden="true"
              />
            )}
            {title && (
              <h3 className="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">
                {title}
              </h3>
            )}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={`p-5 ${bodyClassName}`}>{children}</div>
    </section>
  )
}
