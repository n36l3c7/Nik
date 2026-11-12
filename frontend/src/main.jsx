import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import { AuditProvider } from './context/AuditContext.jsx'
import { AuthProvider } from './context/AuthContext.jsx'
import { SettingsProvider } from './context/SettingsContext.jsx'
import { IncidentProvider } from './context/IncidentContext.jsx'
import { ArtifactProvider } from './context/ArtifactContext.jsx'
import { IocLookupProvider } from './context/IocLookupContext.jsx'
import { IocLibraryProvider } from './context/IocLibraryContext.jsx'
import { ContextMenuProvider } from './context/ContextMenuContext.jsx'
import { NavigationProvider } from './context/NavigationContext.jsx'
import { ToastProvider } from './context/ToastContext.jsx'
import './index.css'

// Application entry point.
// Global providers: audit log, authentication, settings, incidents; then the
// artifact registry (files, e-mails and captures analysed on their own) and the
// app-wide helpers any component can use: navigation requests (tab, search,
// import), toasts, the right-click menu and the indicator lookup/allowlist.
// Audit sits above Auth so it can receive the actor explicitly (no cycle) and
// be driven by Auth (refresh on login/logout). Settings and Incident sit below
// Auth and load their data from the API only once the user is authenticated.
createRoot(document.getElementById('root')).render(
  <StrictMode>
    <AuditProvider>
      <AuthProvider>
        <SettingsProvider>
          <IncidentProvider>
            <ArtifactProvider>
              <NavigationProvider>
                <ToastProvider>
                  <ContextMenuProvider>
                    <IocLookupProvider>
                      <IocLibraryProvider>
                        <App />
                      </IocLibraryProvider>
                    </IocLookupProvider>
                  </ContextMenuProvider>
                </ToastProvider>
              </NavigationProvider>
            </ArtifactProvider>
          </IncidentProvider>
        </SettingsProvider>
      </AuthProvider>
    </AuditProvider>
  </StrictMode>,
)
