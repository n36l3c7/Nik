/**
 * Badge — compact pill label, used for file formats,
 * detection severities, counts, etc.
 */

// Color → classes map (always with a dark counterpart)
const COLORS = {
  slate:
    'bg-slate-100 text-slate-600 border-slate-200 ' +
    'dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
  cyan:
    'bg-cyan-50 text-cyan-700 border-cyan-200 ' +
    'dark:bg-cyan-500/10 dark:text-cyan-400 dark:border-cyan-500/30',
  red:
    'bg-red-50 text-red-700 border-red-200 ' +
    'dark:bg-red-500/10 dark:text-red-400 dark:border-red-500/30',
  amber:
    'bg-amber-50 text-amber-700 border-amber-200 ' +
    'dark:bg-amber-500/10 dark:text-amber-400 dark:border-amber-500/30',
  emerald:
    'bg-emerald-50 text-emerald-700 border-emerald-200 ' +
    'dark:bg-emerald-500/10 dark:text-emerald-400 dark:border-emerald-500/30',
}

export default function Badge({ color = 'slate', children, title, className = '' }) {
  return (
    <span
      title={title}
      className={[
        'inline-flex items-center gap-1 whitespace-nowrap rounded-full border',
        'px-2 py-0.5 text-[11px] font-medium leading-4',
        COLORS[color] ?? COLORS.slate,
        className,
      ].join(' ')}
    >
      {children}
    </span>
  )
}
