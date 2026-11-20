import { Search } from 'lucide-react'
import { useNavigation } from '../../context/NavigationContext.jsx'

/*
 * The search bar in the middle of a page's header. It looks like a search
 * field and is the way into the one search of the application: pressing it
 * opens the palette (CommandPalette.jsx), as Ctrl+K and "/" do, where the
 * typing happens. Every page that takes the area next to the rail has it in
 * its header, so the search is in the same place wherever one is.
 *
 * The bar is as wide as the header has room for (the header is the container
 * its width is read from), and gives way first when there is little: it
 * shrinks down to its magnifier before it pushes anything else out. A header
 * puts it between two sides that grow alike, which is what keeps it in the
 * middle.
 */

/** @param {{ className?: string }} props */
export default function SearchBar({ className = '' }) {
  const { openSearch } = useNavigation()
  return (
    <div
      className={`flex min-w-9 flex-[0_1_16rem] justify-center @5xl:flex-[0_1_22rem] @7xl:flex-[0_1_26rem] ${className}`}
    >
      <button
        type="button"
        onClick={() => openSearch('')}
        aria-label="Search"
        aria-keyshortcuts="Control+K"
        title="Search incidents, indicators, samples and events (Ctrl/Cmd+K or /)"
        className="flex h-9 w-full min-w-9 items-center gap-2 overflow-hidden border border-line bg-canvas px-2.5 text-left text-sm text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <Search className="h-4 w-4 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate">Search</span>
        <kbd className="hidden shrink-0 border border-line px-1 font-mono text-[10px] text-fg-subtle sm:inline">
          Ctrl K
        </kbd>
      </button>
    </div>
  )
}
