import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { X } from 'lucide-react'

/*
 * Short notices at the bottom of the screen, optionally with one action
 * (typically "Undo"). showToast({ message, action: { label, run }, duration }).
 */

const ToastContext = createContext(null)
let nextId = 1

function Toast({ toast, onClose }) {
  useEffect(() => {
    const timer = setTimeout(onClose, toast.duration ?? 6000)
    return () => clearTimeout(timer)
  }, [toast, onClose])
  return (
    <div
      role="status"
      className="pointer-events-auto flex max-w-lg items-center gap-3 border border-line bg-raised px-3 py-2 text-sm text-fg shadow-2xl"
    >
      <span className="min-w-0 flex-1">{toast.message}</span>
      {toast.action && (
        <button
          type="button"
          onClick={() => {
            toast.action.run()
            onClose()
          }}
          className="shrink-0 border border-line px-2 py-0.5 text-xs font-medium text-accent hover:bg-panel focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {toast.action.label}
        </button>
      )}
      <button
        type="button"
        onClick={onClose}
        aria-label="Dismiss"
        className="shrink-0 p-0.5 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])
  const showToast = useCallback((toast) => {
    const id = nextId++
    setToasts((list) => [...list.slice(-2), { ...toast, id }])
    return id
  }, [])
  const close = useCallback((id) => setToasts((list) => list.filter((t) => t.id !== id)), [])
  const value = useMemo(() => ({ showToast }), [showToast])
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed inset-x-0 bottom-4 z-[60] flex flex-col items-center gap-2 px-4">
        {toasts.map((toast) => (
          <Toast key={toast.id} toast={toast} onClose={() => close(toast.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>')
  return ctx
}
