/**
 * Button — reusable button of the CSAP design system.
 *
 * Variants: 'primary' (solid cyan), 'secondary' (border, surface),
 * 'ghost' (transparent), 'danger' (solid red).
 * Sizes: 'md' | 'sm' | 'xs'. Optional lucide icon on the left;
 * without children it becomes an icon-only button (use aria-label).
 */

// Classes per variant: every color has a dark/light counterpart
const VARIANTS = {
  primary:
    'bg-cyan-600 hover:bg-cyan-500 text-white border border-transparent shadow-sm',
  secondary:
    'bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 ' +
    'dark:bg-slate-900 dark:hover:bg-slate-800 dark:text-slate-200 dark:border-slate-700',
  ghost:
    'bg-transparent hover:bg-slate-100 text-slate-600 border border-transparent ' +
    'dark:hover:bg-slate-800 dark:text-slate-300',
  danger:
    'bg-red-600 hover:bg-red-500 text-white border border-transparent shadow-sm',
}

// Classes per size (padding, text, icon spacing)
const SIZES = {
  md: 'px-4 py-2 text-sm gap-2',
  sm: 'px-3 py-1.5 text-sm gap-1.5',
  xs: 'px-2 py-1 text-xs gap-1',
}

// Icon size consistent with the button size
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
        'inline-flex items-center justify-center rounded-lg font-medium',
        'transition-colors select-none',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
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
