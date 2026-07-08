import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import { ThemeProvider } from './context/ThemeContext.jsx'
import { AuditProvider } from './context/AuditContext.jsx'
import { AuthProvider } from './context/AuthContext.jsx'
import { SettingsProvider } from './context/SettingsContext.jsx'
import { IncidentProvider } from './context/IncidentContext.jsx'
import './index.css'

// Application entry point.
// Global providers: theme, audit log, authentication, settings, incidents.
// Audit sits above Auth so it can receive the actor explicitly (no cycle) and
// be driven by Auth (refresh on login/logout). Settings and Incident sit below
// Auth and load their data from the API only once the user is authenticated.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ThemeProvider>
      <AuditProvider>
        <AuthProvider>
          <SettingsProvider>
            <IncidentProvider>
              <App />
            </IncidentProvider>
          </SettingsProvider>
        </AuthProvider>
      </AuditProvider>
    </ThemeProvider>
  </StrictMode>,
)
