import React, { useState } from 'react';
import { ThumbsUp, ThumbsDown, Check } from 'lucide-react';
import { apiService } from '../../services/api';
import { useToast } from '../../context/ToastContext';

interface FixOutcomeButtonsProps {
  vendor: string;
  controlId: string;
  hostname?: string | null;
}

/** "This fix worked" / "This fix failed" - tells ZENTRA's memory how a generated fix really went. */
export function FixOutcomeButtons({ vendor, controlId, hostname }: FixOutcomeButtonsProps) {
  const [mode, setMode] = useState<'idle' | 'asking' | 'done'>('idle');
  const [result, setResult] = useState<boolean | null>(null);
  const [notes, setNotes] = useState('');
  const [busy, setBusy] = useState(false);
  const { showToast } = useToast();

  const send = async (worked: boolean) => {
    setBusy(true);
    try {
      const res = await apiService.reportRemediationOutcome({ vendor, controlId, hostname, worked, notes: notes.trim() });
      setResult(worked);
      setMode('done');
      showToast(
        res.stored ? 'Outcome saved to memory' : 'Outcome logged (Memory is OFF)',
        res.stored
          ? 'ZENTRA will use this the next time a similar fix is generated.'
          : 'Turn Memory ON so outcomes are remembered.',
        res.stored ? 'success' : 'info'
      );
    } catch (err: any) {
      showToast('Could not save outcome', err.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  if (mode === 'done') {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
        <Check className="w-3.5 h-3.5 text-emerald-400" />
        Marked as {result ? 'worked' : 'failed'}
      </span>
    );
  }

  if (mode === 'asking') {
    return (
      <span className="flex items-center gap-1.5 flex-1 min-w-[220px]">
        <input
          autoFocus
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && send(false)}
          placeholder="What went wrong? (e.g. needed a service restart)"
          className="flex-1 px-2 py-1 rounded border border-rose-500/40 bg-slate-950 text-[11px] text-slate-200 focus:outline-none"
        />
        <button type="button" disabled={busy} onClick={() => send(false)} className="px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-[11px] disabled:opacity-50">Save</button>
        <button type="button" onClick={() => setMode('idle')} className="px-2 py-1 rounded border border-slate-700 text-slate-400 text-[11px]">Cancel</button>
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5">
      <button type="button" disabled={busy} onClick={() => send(true)} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-emerald-600/50 text-emerald-300 hover:bg-emerald-950/40 disabled:opacity-50">
        <ThumbsUp className="w-3 h-3" /> This fix worked
      </button>
      <button type="button" disabled={busy} onClick={() => setMode('asking')} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-rose-600/50 text-rose-300 hover:bg-rose-950/40 disabled:opacity-50">
        <ThumbsDown className="w-3 h-3" /> This fix failed
      </button>
    </span>
  );
}
