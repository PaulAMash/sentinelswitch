import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'

export interface ToastInput {
  title: string
  detail?: string
  tone?: 'ok' | 'warn' | 'danger' | 'info'
}
interface ToastItem extends ToastInput {
  id: number
}
const Ctx = createContext<{ push: (t: ToastInput) => void }>({ push: () => undefined })

/** Bottom-right, non-blocking feedback for completed actions; errors stay inline where they happened. */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const seq = useRef(0)
  const push = useCallback((t: ToastInput) => {
    const id = ++seq.current
    setItems((prev) => [...prev, { ...t, id }])
    setTimeout(() => setItems((prev) => prev.filter((i) => i.id !== id)), 4500)
  }, [])
  const value = useMemo(() => ({ push }), [push])
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast ${t.tone ?? 'info'}`}>
            <div className="t">{t.title}</div>
            {t.detail && <div className="d">{t.detail}</div>}
          </div>
        ))}
      </div>
    </Ctx.Provider>
  )
}

export function useToast() {
  return useContext(Ctx)
}
