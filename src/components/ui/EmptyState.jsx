/**
 * EmptyState — standard empty state: prominent icon (or a larger
 * `illustration` node, e.g. an <AsciiSkull />), title, explanatory message
 * and an optional action (e.g. a button).
 */
export default function EmptyState({
  icon: Icon = null,
  illustration = null,
  title,
  message,
  action = null,
  className = '',
}) {
  return (
    <div
      className={[
        'flex flex-col items-center justify-center gap-3 text-center',
        'border border-dashed border-line bg-panel/40 px-6 py-14',
        className,
      ].join(' ')}
    >
      {illustration}
      {!illustration && Icon && (
        <div className="flex h-14 w-14 items-center justify-center border border-line bg-panel">
          <Icon className="h-7 w-7 text-fg-muted" aria-hidden="true" />
        </div>
      )}
      <h3 className="font-mono text-base font-semibold text-fg">{title}</h3>
      {message && <p className="max-w-md text-sm text-fg-muted">{message}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}
