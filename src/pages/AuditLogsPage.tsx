import React, { useState, useEffect } from 'react';
import {
  History,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  Lock,
  ExternalLink,
  Copy,
  Check,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { AuditLogEntry } from '../types';
import { apiService } from '../services/api';
import { useToast } from '../context/ToastContext';

export function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    isValid: boolean;
    brokenAtLogId?: string;
    totalChecked: number;
  } | null>(null);
  const [search, setSearch] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const { showToast } = useToast();

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const data = await apiService.getAuditLogs();
      setLogs(data);
    } catch (err: any) {
      showToast('Error loading audit ledger', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const handleVerifyChain = async () => {
    try {
      setIsVerifying(true);
      const res = await apiService.verifyAuditChain();
      setVerificationResult(res);
      if (res.isValid) {
        showToast(
          'Cryptographic Integrity Verified',
          `Checked ${res.totalChecked} sequential blocks. All SHA-256 link hashes are mathematically authentic.`,
          'success'
        );
      } else {
        showToast(
          'Chain Compromised',
          `Integrity failure detected at block ${res.brokenAtLogId}.`,
          'error'
        );
      }
      fetchLogs();
    } catch (err: any) {
      showToast('Integrity verification failed', err.message, 'error');
    } finally {
      setIsVerifying(false);
    }
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    showToast('Hash copied', '', 'info');
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredLogs = logs.filter(
    (l) =>
      l.action.toLowerCase().includes(search.toLowerCase()) ||
      l.resource.toLowerCase().includes(search.toLowerCase()) ||
      l.user.toLowerCase().includes(search.toLowerCase()) ||
      l.details.toLowerCase().includes(search.toLowerCase()) ||
      l.hash.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 text-left">
      {/* Header & Verification Button */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-5 rounded-xl border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/20 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 border border-cyan-500/40 text-cyan-300">
              TAMPER-EVIDENT LEDGER
            </span>
            <span className="text-xs text-slate-400 font-mono">• SHA-256 Forward Hash Chaining</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight mt-1">
            Immutable Audit Trail & Cryptographic Verification
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-0.5">
            Every state mutation, security scan, finding triage, and policy override is committed to a forward-linked cryptographic chain.
          </p>
        </div>

        <button
          onClick={handleVerifyChain}
          disabled={isVerifying}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer self-start md:self-auto"
        >
          <ShieldCheck className={`w-4 h-4 ${isVerifying ? 'animate-spin' : ''}`} />
          <span>{isVerifying ? 'Verifying Hashes...' : 'Verify Cryptographic Chain'}</span>
        </button>
      </div>

      {/* Verification Result Banner */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border flex items-center justify-between gap-4 ${
            verificationResult.isValid
              ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-950/40 border-rose-500/40 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-3">
            {verificationResult.isValid ? (
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
            ) : (
              <AlertTriangle className="w-6 h-6 text-rose-400 shrink-0" />
            )}
            <div>
              <p className="text-sm font-bold">
                {verificationResult.isValid
                  ? 'Cryptographic Chain 100% Intact & Untampered'
                  : 'Ledger Hash Mismatch Detected!'}
              </p>
              <p className="text-xs text-slate-300 mt-0.5">
                Successfully recomputed and validated SHA-256 hashes across{' '}
                <strong className="text-cyan-300">{verificationResult.totalChecked} ledger blocks</strong>. Zero bit-flips or unauthorized log deletions detected.
              </p>
            </div>
          </div>
          <span className="text-xs font-mono font-bold px-2 py-1 rounded bg-slate-900 border border-slate-700 shrink-0">
            {verificationResult.isValid ? 'ATTESTED' : 'INVALID'}
          </span>
        </div>
      )}

      {/* Filter Bar */}
      <Card className="p-4">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search audit actions, resources, operator emails, or SHA-256 hashes..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </Card>

      {/* Logs Table */}
      <Card
        title={`Audit Log Records (${filteredLogs.length})`}
        subtitle="Chronological sequence with forward cryptographic link"
      >
        {loading ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono">
            Loading cryptographic audit records...
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase tracking-wider text-[10px]">
                  <th className="pb-3 pr-4">Timestamp</th>
                  <th className="pb-3 pr-4">Action</th>
                  <th className="pb-3 pr-4">Resource</th>
                  <th className="pb-3 pr-4">Operator</th>
                  <th className="pb-3 pr-4">Details</th>
                  <th className="pb-3 pr-4">IP Address</th>
                  <th className="pb-3 text-right">SHA-256 Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-850/50 transition">
                    <td className="py-3 pr-4 text-slate-400 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>

                    <td className="py-3 pr-4 font-bold text-cyan-400 whitespace-nowrap">
                      {log.action}
                    </td>

                    <td className="py-3 pr-4 font-sans font-semibold text-slate-200 whitespace-nowrap">
                      {log.resource}
                    </td>

                    <td className="py-3 pr-4 font-sans text-slate-300 whitespace-nowrap">
                      <div>
                        <span>{log.user}</span>
                        <span className="text-[10px] font-mono text-slate-500 block">
                          [{log.role}]
                        </span>
                      </div>
                    </td>

                    <td className="py-3 pr-4 font-sans text-slate-300 max-w-sm">
                      <p className="line-clamp-2">{log.details}</p>
                    </td>

                    <td className="py-3 pr-4 text-slate-500 whitespace-nowrap">
                      {log.ipAddress}
                    </td>

                    <td className="py-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => copyHash(log.hash)}
                        title={`Previous Hash: ${log.previousHash}\nClick to copy current hash`}
                        className="inline-flex items-center gap-1.5 font-mono text-[10px] text-slate-400 hover:text-cyan-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 hover:border-cyan-500/30 transition cursor-pointer"
                      >
                        {copiedHash === log.hash ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Lock className="w-3 h-3 text-cyan-500" />
                        )}
                        <span>{log.hash.substring(0, 10)}...</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
