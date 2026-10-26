import React, { useEffect, useState } from 'react';
import { Brain, RefreshCw, Database, FileSearch, Loader2, CheckCircle2, CloudOff } from 'lucide-react';
import { Card } from '../components/common/Card';
import { apiService, MemoryJournalEntry, MemoryStatus } from '../services/api';
import { useToast } from '../context/ToastContext';

const CONTEXT_STYLES: Record<string, { label: string; cls: string }> = {
  'finding-decision': { label: 'Finding decision', cls: 'border-purple-500/40 bg-purple-950/40 text-purple-300' },
  'compliance-result': { label: 'Compliance result', cls: 'border-rose-500/40 bg-rose-950/40 text-rose-300' },
  'remediation-generated': { label: 'Fix generated', cls: 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300' },
  'remediation-outcome': { label: 'Fix outcome', cls: 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300' },
  'analyst-teaching': { label: 'Analyst teaching', cls: 'border-amber-500/40 bg-amber-950/40 text-amber-300' },
  'scan-summary': { label: 'Scan summary', cls: 'border-indigo-500/40 bg-indigo-950/40 text-indigo-300' },
  'vendor-quirk': { label: 'Vendor quirk', cls: 'border-orange-500/40 bg-orange-950/40 text-orange-300' },
};

export function MemoryPage() {
  const [entries, setEntries] = useState<MemoryJournalEntry[]>([]);
  const [status, setStatus] = useState<MemoryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [target, setTarget] = useState('');
  const [briefing, setBriefing] = useState<{ text: string; available: boolean } | null>(null);
  const [briefLoading, setBriefLoading] = useState(false);
  const { showToast } = useToast();

  const load = async () => {
    try {
      setLoading(true);
      const res = await apiService.getRecentMemories();
      setEntries(res.entries);
      setStatus(res.status);
    } catch (err: any) {
      showToast('Could not load memory', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSeed = async () => {
    setSeeding(true);
    try {
      const res = await apiService.seedMemory();
      showToast('Sample memory loaded', `${res.stored} of ${res.total} events sent to Hindsight. It may take a minute to be searchable.`, 'success');
      await load();
    } catch (err: any) {
      showToast('Could not load sample memory', err.message, 'error');
    } finally {
      setSeeding(false);
    }
  };

  const handleBrief = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    setBriefLoading(true);
    setBriefing(null);
    try {
      setBriefing(await apiService.getMemoryBrief(target.trim()));
    } catch (err: any) {
      showToast('Could not get briefing', err.message, 'error');
    } finally {
      setBriefLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Brain className="w-6 h-6 text-fuchsia-400" />
            Agent Memory
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            What ZENTRA remembers about this organisation: findings, risk decisions, fix outcomes and vendor quirks. Powered by Hindsight.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load} className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-300 hover:bg-slate-800 flex items-center gap-1.5">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
          <button
            onClick={handleSeed}
            disabled={seeding}
            className="px-3 py-1.5 rounded-lg bg-fuchsia-600 hover:bg-fuchsia-500 text-xs font-semibold text-white flex items-center gap-1.5 disabled:opacity-60"
          >
            {seeding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5" />}
            Load sample memory
          </button>
        </div>
      </div>

      {status && (
        <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono">
          <span className={`px-2 py-1 rounded border ${status.enabled ? 'border-fuchsia-500/40 text-fuchsia-300 bg-fuchsia-950/30' : 'border-slate-700 text-slate-400 bg-slate-900'}`}>
            Memory {status.enabled ? 'ON' : 'OFF'}
          </span>
          <span className={`px-2 py-1 rounded border flex items-center gap-1.5 ${status.connected ? 'border-emerald-500/40 text-emerald-300 bg-emerald-950/30' : 'border-slate-700 text-slate-400 bg-slate-900'}`}>
            {status.connected ? <CheckCircle2 className="w-3 h-3" /> : <CloudOff className="w-3 h-3" />}
            {status.connected ? 'Connected' : status.configured ? 'Not connected' : 'Not configured'}
          </span>
          <span className="text-slate-500">bank: {status.bankId}{status.host ? ` @ ${status.host}` : ''}</span>
          {status.lastError && <span className="text-amber-400 truncate max-w-full">{status.lastError}</span>}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        {/* Briefing */}
        <div className="xl:col-span-2">
          <Card
            title={
              <div className="flex items-center gap-2">
                <FileSearch className="w-4 h-4 text-cyan-400" />
                <span>Audit readiness briefing</span>
              </div>
            }
            subtitle="Ask memory what failed before, what was accepted, and what needs attention."
          >
            <form onSubmit={handleBrief} className="space-y-3">
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Device or API name, e.g. LEAF01-POD2"
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                disabled={briefLoading || !target.trim()}
                className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white disabled:opacity-50 flex items-center gap-1.5"
              >
                {briefLoading && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                Get audit briefing
              </button>
            </form>
            {briefLoading && <p className="mt-4 text-xs text-slate-400">Reasoning over memory... this can take up to 30 seconds.</p>}
            {briefing && (
              <div className={`mt-4 p-3.5 rounded-lg border text-xs leading-relaxed whitespace-pre-wrap select-text ${briefing.available ? 'border-slate-800 bg-slate-950 text-slate-200' : 'border-amber-500/30 bg-amber-950/20 text-amber-200'}`}>
                {briefing.text}
              </div>
            )}
          </Card>
        </div>

        {/* Timeline */}
        <div className="xl:col-span-3">
          <Card
            title={
              <div className="flex items-center gap-2">
                <Brain className="w-4 h-4 text-fuchsia-400" />
                <span>Recent memories</span>
              </div>
            }
            subtitle={`${entries.length} most recent events sent to memory`}
          >
            {entries.length === 0 ? (
              <div className="py-10 text-center text-xs text-slate-400 space-y-2">
                <Brain className="w-8 h-8 mx-auto text-slate-600" />
                <p>No memories yet.</p>
                <p>Change a finding's status, run a compliance evaluation, or click "Load sample memory" to fill it with realistic history.</p>
              </div>
            ) : (
              <ol className="relative border-l border-slate-800 ml-2 space-y-4 max-h-[640px] overflow-y-auto pr-2">
                {entries.map((m) => {
                  const style = CONTEXT_STYLES[m.context] || { label: m.context, cls: 'border-slate-600 bg-slate-900 text-slate-300' };
                  return (
                    <li key={m.id} className="ml-4">
                      <span className="absolute -left-[5px] mt-1.5 w-2.5 h-2.5 rounded-full bg-fuchsia-500/70 border border-slate-900" />
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono mb-1">
                        <span className={`px-1.5 py-0.5 rounded border ${style.cls}`}>{style.label}</span>
                        <span className="text-slate-500">{new Date(m.at).toLocaleString()}</span>
                        <span className={m.synced ? 'text-emerald-400' : 'text-slate-500'}>{m.synced ? 'synced' : 'not synced'}</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed select-text">{m.content}</p>
                    </li>
                  );
                })}
              </ol>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
