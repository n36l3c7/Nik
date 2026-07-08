/**
 * EmptyState — standard empty state: prominent icon, title,
 * explanatory message and an optional action (e.g. a button).
 */
export default function EmptyState({
  icon: Icon = null,
  title,
  message,
  action = null,
  className = '',
}) {
  return (
    <div
      className={[
        'flex flex-col items-center justify-center gap-3 text-center',
        'rounded-xl border border-dashed border-slate-300 bg-white/60 px-6 py-14',
        'dark:border-slate-700 dark:bg-slate-900/40',
        className,
      ].join(' ')}
    >
      {Icon && (
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 dark:bg-slate-800">
          <Icon className="h-7 w-7 text-slate-400 dark:text-slate-500" aria-hidden="true" />
        </div>
      )}
      <h3 className="text-base font-semibold text-slate-700 dark:text-slate-200">{title}</h3>
      {message && (
        <p className="max-w-md text-sm text-slate-500 dark:text-slate-400">{message}</p>
      )}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
