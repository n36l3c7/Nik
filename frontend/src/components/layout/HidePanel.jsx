import { PanelLeftClose } from 'lucide-react'

/*
 * The button in the header of a side panel (artifacts, indicators) that hides
 * it. The entry of the rail shows the panel and never hides it, so this is
 * the way to give the main area its whole width back; the panel stays hidden
 * until its entry is pressed again.
 */

/** @param {{ label: string, onClick: () => void }} props */
export default function HidePanel({ label, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="-mr-2 flex h-8 w-6 shrink-0 items-center justify-center text-fg-muted transition-colors hover:bg-panel hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
    >
      <PanelLeftClose className="h-4 w-4" aria-hidden="true" />
    </button>
  )
}
