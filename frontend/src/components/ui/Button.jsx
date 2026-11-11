/**
 * Button — reusable button of the Nik design system (terminal look).
 *
 * Variants: 'primary' (solid green), 'secondary' (outlined), 'ghost'
 * (transparent), 'danger' (solid red). Sizes: 'md' | 'sm' | 'xs', each
 * with a fixed height (36, 32, 28 px) so buttons side by side line up
 * whatever they hold. Optional lucide icon on the left; without children it
 * becomes a square icon-only button (give it an aria-label).
 */
const VARIANTS = {
  primary: 'bg-accent text-canvas hover:bg-accent-fg border border-transparent font-semibold',
  secondary: 'bg-transparent text-fg border border-line hover:bg-raised',
  ghost: 'bg-transparent text-fg-muted border border-transparent hover:bg-raised hover:text-fg',
  danger: 'bg-high-line text-white hover:bg-high border border-transparent font-semibold',
}

const SIZES = {
  md: 'h-9 px-4 text-sm gap-2',
  sm: 'h-8 px-3 text-sm gap-1.5',
  xs: 'h-7 px-2 text-xs gap-1',
}

// Icon-only: as wide as it is tall.
const SQUARE = {
  md: 'h-9 w-9',
  sm: 'h-8 w-8',
  xs: 'h-7 w-7',
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
        'shrink-0 whitespace-nowrap',
        VARIANTS[variant] ?? VARIANTS.primary,
        children == null || children === false ? (SQUARE[size] ?? SQUARE.md) : (SIZES[size] ?? SIZES.md),
        className,
      ].join(' ')}
      {...rest}
    >
      {Icon && <Icon className={`shrink-0 ${ICON_SIZES[size] ?? ICON_SIZES.md}`} aria-hidden="true" />}
      {children}
    </button>
  )
}
