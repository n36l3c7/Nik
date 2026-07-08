import { Loader2 } from 'lucide-react'

/**
 * Spinner — loading indicator (a spinning Loader2).
 * If `className` does not specify a size, the default is h-5 w-5.
 */
export default function Spinner({ className = '' }) {
  return (
    <Loader2
      role="status"
      aria-label="Loading"
      className={`animate-spin text-cyan-600 dark:text-cyan-400 ${className || 'h-5 w-5'}`}
    />
  )
}
