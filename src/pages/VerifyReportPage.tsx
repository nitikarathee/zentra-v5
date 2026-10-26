import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, UploadCloud, FileCheck2, RotateCw } from 'lucide-react';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

type Result = { verdict: 'AUTHENTIC' | 'TAMPERED'; checkedAt: string } | null;

export function VerifyReportPage() {
  const { showToast } = useToast();
  const [data, setData] = useState('');
  const [seal, setSeal] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result>(null);

  // Accepts a *.seal.json (or the seal file inside a ZIP): { seal, payload }
  const handleFile = async (file: File | undefined) => {
    if (!file) return;
    const text = await file.text();
    setResult(null);
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.payload && parsed.seal) {
        setData(JSON.stringify(parsed.payload, null, 2));
        setSeal(String(parsed.seal));
        return;
      }
    } catch {
      // not JSON: show as-is so the user sees why it fails
    }
    setData(text);
  };

  const handleVerify = async () => {
    setResult(null);
    let payload: any;
    try {
      payload = JSON.parse(data);
    } catch {
      showToast('Invalid report data', 'Report data must be the JSON from the .seal.json file.', 'error');
      return;
    }
    if (!seal.trim()) {
      showToast('Seal missing', 'Paste the seal hash printed on the last page of the PDF.', 'error');
      return;
    }
    try {
      setBusy(true);
      const res = await apiService.verifyReport(payload, seal.trim());
      setResult({ verdict: res.verdict, checkedAt: res.checkedAt });
    } catch (err: any) {
      showToast('Verification failed', err.message, 'error');
    } finally {
      setBusy(false);
    }
  };

  const ok = result?.verdict === 'AUTHENTIC';

  return (
    <div className="space-y-5 max-w-3xl">
      <div>
        <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
          <FileCheck2 className="w-5 h-5 text-cyan-400" />
          Verify Report
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Every ZENTRA report carries an HMAC-SHA256 seal made with this server's secret key. Upload the report's
          <span className="font-mono text-cyan-300"> .seal.json </span>
          (or paste its data and the seal from the PDF's last page). The server recomputes the seal; any edited word fails.
        </p>
      </div>

      <label className="flex items-center justify-center gap-2 p-5 border border-dashed border-slate-700 rounded-xl text-xs text-slate-400 hover:border-cyan-500/50 cursor-pointer">
        <UploadCloud className="w-4 h-4" />
        <span>Upload report seal file (.seal.json)</span>
        <input type="file" accept=".json,application/json" className="hidden" onChange={(e) => handleFile(e.target.files?.[0])} />
      </label>

      <div className="space-y-1.5">
        <span className="text-[11px] uppercase tracking-wider text-slate-500">Report data (JSON)</span>
        <textarea
          value={data}
          onChange={(e) => { setData(e.target.value); setResult(null); }}
          rows={12}
          spellCheck={false}
          className="w-full p-3 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-cyan-200 focus:outline-none focus:border-cyan-500"
          placeholder="Paste report data here, or upload the .seal.json above"
        />
      </div>

      <div className="space-y-1.5">
        <span className="text-[11px] uppercase tracking-wider text-slate-500">Seal (64-char hash)</span>
        <input
          value={seal}
          onChange={(e) => { setSeal(e.target.value); setResult(null); }}
          spellCheck={false}
          className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg font-mono text-[11px] text-slate-200 focus:outline-none focus:border-cyan-500"
          placeholder="e.g. 9f2c...  (printed on the last page of the PDF)"
        />
      </div>

      <button
        type="button"
        onClick={handleVerify}
        disabled={busy || !data.trim()}
        className="px-4 py-2 text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg flex items-center gap-1.5"
      >
        {busy ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
        Verify Report
      </button>

      {result && (
        <div
          className={`p-5 rounded-xl border flex items-center gap-3 ${
            ok ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-300' : 'bg-rose-950/30 border-rose-500/60 text-rose-300'
          }`}
        >
          {ok ? <ShieldCheck className="w-8 h-8" /> : <ShieldAlert className="w-8 h-8" />}
          <div>
            <div className="text-lg font-extrabold tracking-wide">{ok ? 'AUTHENTIC' : 'TAMPERED'}</div>
            <div className="text-[11px] opacity-80">
              {ok
                ? 'Seal matches the report contents. Nothing was changed since it was generated.'
                : 'Seal does NOT match. The report was modified after sealing, or the seal is forged.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
