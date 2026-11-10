/**
 * Button — reusable button of the Nik design system (terminal look).
 *
 * Variants: 'primary' (solid green), 'secondary' (outlined), 'ghost'
 * (transparent), 'danger' (solid red). Sizes: 'md' | 'sm' | 'xs'.
 * Optional lucide icon on the left; without children it becomes an
 * icon-only button (give it an aria-label).
 */
const VARIANTS = {
  primary: 'bg-accent text-canvas hover:bg-accent-fg border border-transparent font-semibold',
  secondary: 'bg-transparent text-fg border border-line hover:bg-raised',
  ghost: 'bg-transparent text-fg-muted border border-transparent hover:bg-raised hover:text-fg',
  danger: 'bg-high-line text-white hover:bg-high border border-transparent font-semibold',
}

const SIZES = {
  md: 'px-4 py-2 text-sm gap-2',
  sm: 'px-3 py-1.5 text-sm gap-1.5',
  xs: 'px-2 py-1 text-xs gap-1',
}

const ICON_SIZES = {
  md: 'h-4 w-4',
  sm: 'h-4 w-4',
  xs: 'h-3.5 w-3.5',
}

export default function Button({
  variant = 'primary',
  size = 'md',
  icon: Icon = null,
  children,
  className = '',
  disabled = false,
  type = 'button',
  ...rest
}) {
  return (
    <button
      type={type}
      disabled={disabled}
      className={[
        'inline-flex items-center justify-center font-medium',
        'transition-colors select-none',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        'disabled:opacity-50 disabled:cursor-not-allowed disabled:pointer-events-none',
        VARIANTS[variant] ?? VARIANTS.primary,
        SIZES[size] ?? SIZES.md,
        className,
      ].join(' ')}
      {...rest}
    >
      {Icon && <Icon className={`shrink-0 ${ICON_SIZES[size] ?? ICON_SIZES.md}`} aria-hidden="true" />}
      {children}
    </button>
  )
}
