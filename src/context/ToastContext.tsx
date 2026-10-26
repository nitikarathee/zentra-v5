import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  title: string;
  message?: string;
  type: ToastType;
}

interface ToastContextType {
  toasts: Toast[];
  showToast: (title: string, message?: string, type?: ToastType) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback((title: string, message?: string, type: ToastType = 'info') => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const newToast: Toast = { id, title, message, type };
    setToasts((prev) => [...prev, newToast]);

    setTimeout(() => {
      removeToast(id);
    }, 4500);
  }, [removeToast]);

  return (
    <ToastContext.Provider value={{ toasts, showToast, removeToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none">
        {toasts.map((toast) => {
          let Icon = Info;
          let borderClass = 'border-cyan-500/30 bg-slate-900/90 text-cyan-200';
          let iconColor = 'text-cyan-400';

          if (toast.type === 'success') {
            Icon = CheckCircle2;
            borderClass = 'border-emerald-500/30 bg-slate-900/90 text-emerald-200';
            iconColor = 'text-emerald-400';
          } else if (toast.type === 'error') {
            Icon = XCircle;
            borderClass = 'border-rose-500/30 bg-slate-900/90 text-rose-200';
            iconColor = 'text-rose-400';
          } else if (toast.type === 'warning') {
            Icon = AlertTriangle;
            borderClass = 'border-amber-500/30 bg-slate-900/90 text-amber-200';
            iconColor = 'text-amber-400';
          }

          return (
            <div
              key={toast.id}
              className={`pointer-events-auto flex items-start gap-3 p-3.5 rounded-lg border shadow-xl backdrop-blur-md transition-all duration-200 ${borderClass}`}
            >
              <Icon className={`w-5 h-5 shrink-0 mt-0.5 ${iconColor}`} />
              <div className="flex-1 text-sm">
                <div className="font-semibold text-slate-100">{toast.title}</div>
                {toast.message && <div className="text-xs text-slate-400 mt-0.5">{toast.message}</div>}
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="text-slate-400 hover:text-slate-200 p-1 -mr-1 -mt-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}
