import { createContext, useContext, useEffect, useState } from 'react'
import { loadTheme, saveTheme } from '../services/storage.js'

/*
 * Dark/Light theme management with persistence in localStorage.
 * The `dark` class is applied to <html>, enabling the Tailwind
 * `dark:` variant across the whole app (see @custom-variant in index.css).
 */

const ThemeContext = createContext(null)

export function ThemeProvider({ children }) {
  // Default: dark (SOC dashboard style), unless the user has already
  // chosen a theme in a previous session.
  const [theme, setTheme] = useState(() => loadTheme() ?? 'dark')

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    saveTheme(theme)
  }, [theme])

  const toggleTheme = () =>
    setTheme((current) => (current === 'dark' ? 'light' : 'dark'))

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  )
}

/** Hook to access the theme: { theme, setTheme, toggleTheme } */
export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within <ThemeProvider>')
  return ctx
}
