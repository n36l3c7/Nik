/**
 * Badge — compact square label (terminal look), used for file formats,
 * detection severities, counts, etc.
 *
 * Colour names are kept for compatibility: slate (neutral), cyan (info),
 * red (HIGH), amber (MED), emerald (accent / ok), violet (commands).
 */
const COLORS = {
  slate: 'border-line text-fg-muted',
  cyan: 'border-info-line bg-info-soft/40 text-info',
  red: 'border-high-line bg-high-soft text-high-fg',
  amber: 'border-med-line bg-med-soft text-med-fg',
  emerald: 'border-accent-strong bg-accent-soft text-accent-fg',
  violet: 'border-violet-line bg-violet-soft text-violet',
}

export default function Badge({ color = 'slate', children, title, className = '' }) {
  return (
    <span
      title={title}
      className={[
        'inline-flex items-center gap-1 whitespace-nowrap border',
        'px-1.5 py-px font-mono text-[11px] leading-4',
        COLORS[color] ?? COLORS.slate,
        className,
      ].join(' ')}
    >
      {children}
    </span>
  )
}
