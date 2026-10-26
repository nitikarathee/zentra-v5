import React, { useState, useEffect } from 'react';
import {
  ArrowLeft,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Wrench,
  FileCode,
  Copy,
  Check,
  AlertTriangle,
  Send,
  HelpCircle,
  Brain,
} from 'lucide-react';
import { Card } from '../components/common/Card';
import { Modal } from '../components/common/Modal';
import { SeverityBadge, StatusBadge } from '../components/common/Badge';
import { SecurityFinding, ApiItem, FindingStatus } from '../types';
import { apiService, RecalledMemory } from '../services/api';
import { useToast } from '../context/ToastContext';
import { useAuth } from '../context/AuthContext';

interface FindingDetailPageProps {
  findingId: string;
  onBack: () => void;
  onNavigateRemediation?: () => void;
}

export function FindingDetailPage({ findingId, onBack, onNavigateRemediation }: FindingDetailPageProps) {
  const [finding, setFinding] = useState<SecurityFinding | null>(null);
  const [api, setApi] = useState<ApiItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  // Hindsight memory: "Seen before"
  const [seenBefore, setSeenBefore] = useState<RecalledMemory[]>([]);
  const [seenLoading, setSeenLoading] = useState(false);
  const [memoryOn, setMemoryOn] = useState(true);

  // Accept Risk modal
  const [isAcceptRiskModalOpen, setIsAcceptRiskModalOpen] = useState(false);
  const [acceptedReason, setAcceptedReason] = useState('');

  const { showToast } = useToast();
  const { hasPermission } = useAuth();

  const fetchFinding = async () => {
    try {
      setLoading(true);
      const res = await apiService.getFinding(findingId);
      setFinding(res.finding);
      setApi(res.api);
    } catch (err: any) {
      showToast('Error loading finding', err.message, 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFinding();
  }, [findingId]);

  useEffect(() => {
    if (!finding) return;
    let cancelled = false;
    setSeenLoading(true);
    apiService
      .recallMemories(`${finding.title} on ${finding.apiName} (${finding.category}, ${finding.severity}): earlier findings, risk decisions and fixes`)
      .then((res) => {
        if (cancelled) return;
        setMemoryOn(res.enabled);
        setSeenBefore(res.memories);
      })
      .catch(() => {
        if (!cancelled) setSeenBefore([]);
      })
      .finally(() => {
        if (!cancelled) setSeenLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [finding?.id, finding?.status]);

  const handleUpdateStatus = async (newStatus: FindingStatus, justification?: string) => {
    if (!finding) return;
    try {
      const updated = await apiService.updateFindingStatus(finding.id, newStatus, justification);
      setFinding(updated);
      showToast(
        'Status Updated',
        `Finding ${updated.findingId} marked as ${newStatus.replace('_', ' ')}.`,
        'success'
      );
      setIsAcceptRiskModalOpen(false);
      setAcceptedReason('');
    } catch (err: any) {
      showToast('Status update failed', err.message, 'error');
    }
  };

  const copyToClipboard = (text: string, sectionId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(sectionId);
    showToast('Copied to clipboard', '', 'info');
    setTimeout(() => setCopiedSection(null), 2000);
  };

  if (loading || !finding) {
    return (
      <div className="py-20 text-center text-slate-400 text-xs font-mono">
        Loading finding forensics...
      </div>
    );
  }

  return (
    <div className="space-y-6 text-left">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition cursor-pointer"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-cyan-400">
                {finding.findingId}
              </span>
              <SeverityBadge severity={finding.severity} size="sm" />
              <StatusBadge status={finding.status} size="sm" />
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight mt-1">
              {finding.title}
            </h2>
          </div>
        </div>

        {/* Status Action Buttons */}
        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          {onNavigateRemediation && (
            <button
              onClick={onNavigateRemediation}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 text-xs font-semibold hover:bg-cyan-900/50 transition cursor-pointer"
            >
              <Wrench className="w-3.5 h-3.5" />
              <span>Remediation Playbook</span>
            </button>
          )}

          {finding.status !== 'IN_PROGRESS' && (
            <button
              onClick={() => handleUpdateStatus('IN_PROGRESS')}
              className="px-3 py-1.5 rounded-lg border border-blue-500/40 bg-blue-950/40 text-blue-300 text-xs font-semibold hover:bg-blue-900/50 transition cursor-pointer"
            >
              Mark In Progress
            </button>
          )}

          {finding.status !== 'RESOLVED' && (
            <button
              onClick={() => handleUpdateStatus('RESOLVED')}
              className="px-3 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-950/40 text-emerald-300 text-xs font-semibold hover:bg-emerald-900/50 transition cursor-pointer"
            >
              Mark Resolved
            </button>
          )}

          {finding.status !== 'ACCEPTED_RISK' && hasPermission('finding:accept_risk') && (
            <button
              onClick={() => setIsAcceptRiskModalOpen(true)}
              className="px-3 py-1.5 rounded-lg border border-purple-500/40 bg-purple-950/40 text-purple-300 text-xs font-semibold hover:bg-purple-900/50 transition cursor-pointer"
            >
              Accept Risk
            </button>
          )}
        </div>
      </div>

      {/* Target API & Endpoint Bar */}
      <Card className="p-4 bg-slate-950/60">
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 text-xs font-mono">
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Target API</span>
            <span className="font-semibold text-slate-200 font-sans text-sm">{finding.apiName}</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Endpoint & Method</span>
            <span className="text-cyan-300 font-bold mr-1">{finding.method}</span>
            <span className="text-slate-300">{finding.endpoint}</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">Security Category</span>
            <span className="text-slate-300 font-sans">{finding.category}</span>
          </div>
          <div>
            <span className="text-slate-500 uppercase text-[10px] block">First Detected</span>
            <span className="text-slate-400">{new Date(finding.createdAt).toLocaleDateString()}</span>
          </div>
        </div>
      </Card>

      {/* Accepted Risk Banner (if active) */}
      {finding.status === 'ACCEPTED_RISK' && (
        <div className="p-4 rounded-xl border border-purple-500/40 bg-purple-950/30 flex items-start gap-3">
          <HelpCircle className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
          <div className="text-xs text-purple-200">
            <span className="font-bold block text-sm">Formally Accepted Risk Exception</span>
            <p className="mt-1">{finding.acceptedReason || 'Compensating controls documented and verified.'}</p>
          </div>
        </div>
      )}

      {/* Seen before (Hindsight memory) */}
      <Card
        title={
          <div className="flex items-center gap-2 text-fuchsia-300">
            <Brain className="w-4 h-4" />
            <span>Seen before</span>
          </div>
        }
        subtitle="Related history recalled from ZENTRA's persistent memory"
      >
        {seenLoading ? (
          <p className="text-xs text-slate-400">Searching memory...</p>
        ) : !memoryOn ? (
          <p className="text-xs text-slate-400">Memory is OFF. Turn it ON in the header to see related history for this finding.</p>
        ) : seenBefore.length === 0 ? (
          <p className="text-xs text-slate-400">
            Nothing similar in memory yet. ZENTRA will remember how this finding is handled so it can help the next time something like it appears.
          </p>
        ) : (
          <ul className="space-y-2">
            {seenBefore.slice(0, 6).map((m, i) => (
              <li key={m.id || i} className="p-3 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-300 leading-relaxed select-text">
                {m.date && <span className="block text-[10px] font-mono text-slate-500 mb-0.5">{new Date(m.date).toLocaleDateString()}</span>}
                {m.text}
              </li>
            ))}
          </ul>
        )}
      </Card>

      {/* Deep-Dive Grid: Description & Evidence */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Description & Impact */}
        <div className="space-y-6">
          <Card title="Vulnerability Description">
            <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>
          </Card>

          <Card
            title={
              <div className="flex items-center gap-2 text-rose-400">
                <AlertTriangle className="w-4 h-4" />
                <span>Security & Business Impact</span>
              </div>
            }
          >
            <p className="text-xs text-slate-300 leading-relaxed">{finding.impact}</p>
          </Card>
        </div>

        {/* Evidence & Technical Traces */}
        <Card
          title={
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>Technical Evidence & Trace</span>
            </div>
          }
          action={
            <button
              onClick={() => copyToClipboard(finding.evidence, 'evidence')}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              {copiedSection === 'evidence' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              <span>Copy</span>
            </button>
          }
        >
          <div className="p-3.5 rounded-lg bg-black/80 border border-slate-800 font-mono text-xs text-cyan-200 overflow-x-auto select-text whitespace-pre-wrap">
            {finding.evidence}
          </div>
        </Card>
      </div>

      {/* Remediation & Implementation Guide */}
      <Card
        title={
          <div className="flex items-center gap-2 text-emerald-400">
            <Wrench className="w-4 h-4" />
            <span>Remediation Recommendation</span>
          </div>
        }
      >
        <p className="text-xs text-slate-200 leading-relaxed font-medium mb-4">
          {finding.recommendation}
        </p>

        <div className="space-y-4">
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400 font-mono mb-1.5">
              <span>Implementation Guide & Code Fix:</span>
              <button
                onClick={() => copyToClipboard(finding.implementationGuide, 'impl')}
                className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[11px]"
              >
                {copiedSection === 'impl' ? (
                  <Check className="w-3 h-3 text-emerald-400" />
                ) : (
                  <Copy className="w-3 h-3" />
                )}
                <span>Copy Guide</span>
              </button>
            </div>
            <pre className="p-3.5 rounded-lg bg-black/80 border border-slate-800 font-mono text-xs text-slate-300 overflow-x-auto select-text whitespace-pre-wrap">
              {finding.implementationGuide}
            </pre>
          </div>

          <div>
            <span className="text-xs text-slate-400 font-mono block mb-1.5">
              Validation & Verification Steps:
            </span>
            <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-300 overflow-x-auto select-text whitespace-pre-wrap">
              {finding.validationSteps}
            </pre>
          </div>
        </div>
      </Card>

      {/* Accept Risk Modal */}
      <Modal
        isOpen={isAcceptRiskModalOpen}
        onClose={() => setIsAcceptRiskModalOpen(false)}
        title="Document Risk Acceptance Exception"
        subtitle="Zero-Trust policies mandate explicit business justification and compensating controls"
        maxWidth="md"
      >
        <div className="space-y-4 text-left">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Compensating Control / Business Justification *
            </label>
            <textarea
              rows={4}
              required
              placeholder="e.g. Rate limiting enforced upstream by Cloudflare WAF; dedicated database user with read-only view prevents unauthorized writes..."
              value={acceptedReason}
              onChange={(e) => setAcceptedReason(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              onClick={() => setIsAcceptRiskModalOpen(false)}
              className="px-3 py-1.5 rounded-lg border border-slate-800 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              onClick={() => handleUpdateStatus('ACCEPTED_RISK', acceptedReason)}
              disabled={!acceptedReason.trim()}
              className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-xs font-semibold text-white disabled:opacity-50"
            >
              Confirm Risk Acceptance
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
