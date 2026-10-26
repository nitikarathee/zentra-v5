import React, { useEffect, useState } from 'react';
import { Brain } from 'lucide-react';
import { apiService, MemoryStatus } from '../../services/api';
import { useToast } from '../../context/ToastContext';

/** Header switch: Memory ON/OFF + a dot for the Hindsight connection (green = connected, grey = not). */
export function MemoryToggle({ onClick }: { onClick?: () => void }) {
  const [status, setStatus] = useState<MemoryStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  const refresh = () => apiService.getMemoryStatus().then(setStatus).catch(() => setStatus(null));

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 20000);
    return () => clearInterval(t);
  }, []);

  if (!status) return null;

  const toggle = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const next = await apiService.toggleMemory(!status.enabled);
      setStatus(next);
      showToast(
        next.enabled ? 'Memory ON' : 'Memory OFF',
        next.enabled ? 'ZENTRA will learn from and recall past experience.' : 'ZENTRA answers without past experience and stops saving new memories.',
        'info'
      );
    } catch (err: any) {
      showToast('Could not change memory', err.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const dot = status.connected ? 'bg-emerald-400' : 'bg-slate-500';
  const dotTitle = status.connected
    ? `Connected to Hindsight (bank: ${status.bankId})`
    : status.configured
    ? `Not connected to Hindsight${status.lastError ? ` - ${status.lastError}` : ''}`
    : 'Hindsight not configured (set HINDSIGHT_BASE_URL)';

  return (
    <div
      className={`flex items-center gap-1.5 px-2 py-1 rounded-md border text-[11px] font-mono ${
        status.enabled
          ? 'border-fuchsia-500/40 bg-fuchsia-950/40 text-fuchsia-300'
          : 'border-slate-700 bg-slate-900/60 text-slate-400'
      }`}
    >
      <button type="button" onClick={onClick} title="Open Memory page" className="flex items-center gap-1.5 hover:opacity-80">
        <Brain className="w-3.5 h-3.5" />
        <span>Memory</span>
        <span title={dotTitle} className={`w-2 h-2 rounded-full ${dot}`} />
      </button>
      <button
        type="button"
        role="switch"
        aria-checked={status.enabled}
        aria-label="Toggle agent memory"
        onClick={toggle}
        disabled={busy}
        className={`relative w-8 h-4 rounded-full transition ${status.enabled ? 'bg-fuchsia-500' : 'bg-slate-600'} disabled:opacity-60`}
      >
        <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${status.enabled ? 'left-4' : 'left-0.5'}`} />
      </button>
      <span className="w-6 text-right font-bold">{status.enabled ? 'ON' : 'OFF'}</span>
    </div>
  );
}
