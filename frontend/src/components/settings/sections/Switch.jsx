/** An on/off switch with a name: what the instances of a connector and their fetching are turned on with. */
export default function Switch({ checked, onChange, label, disabled = false }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={checked ? 'On: click to turn it off' : 'Off: click to turn it on'}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={[
        'relative h-4 w-8 shrink-0 border transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        'disabled:cursor-not-allowed disabled:opacity-60',
        checked ? 'border-accent bg-accent-soft' : 'border-line bg-sunken',
      ].join(' ')}
    >
      <span
        aria-hidden="true"
        className={[
          'absolute top-px h-3 w-3 transition-all',
          checked ? 'left-[17px] bg-accent' : 'left-px bg-fg-subtle',
        ].join(' ')}
      />
    </button>
  )
}
