/**
 * The mark of Nik: a prompt on a green square. The same drawing as
 * public/favicon.svg and public/brand/nik-mark.svg, so the rail, the tab of the
 * browser and the documentation show one logo.
 *
 * Decorative by default; give it a `label` where it stands for the name.
 *
 * @param {{ className?: string, label?: string }} props
 */
export default function NikMark({ className = 'h-7 w-7', label = '' }) {
  return (
    <svg
      viewBox="0 0 64 64"
      className={className}
      role={label ? 'img' : undefined}
      aria-label={label || undefined}
      aria-hidden={label ? undefined : 'true'}
    >
      <rect width="64" height="64" fill="var(--color-accent)" />
      <path d="M15 21l13 11-13 11" fill="none" stroke="var(--color-canvas)" strokeWidth="7" strokeLinecap="square" />
      <path d="M35 45h14" fill="none" stroke="var(--color-canvas)" strokeWidth="7" strokeLinecap="square" />
    </svg>
  )
}
