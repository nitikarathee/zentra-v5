import React, { useState, useEffect, useRef } from 'react';
import { Search, Server, ShieldAlert, FileCheck2, ArrowRight, X } from 'lucide-react';
import { ApiItem, SecurityFinding, CISControl } from '../../types';
import { SeverityBadge, StatusBadge } from '../common/Badge';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  apis: ApiItem[];
  findings: SecurityFinding[];
  cisControls: CISControl[];
  onSelectApi: (id: string) => void;
  onSelectFinding: (id: string) => void;
  onNavigateTab: (tab: string) => void;
}

export function GlobalSearchModal({
  isOpen,
  onClose,
  apis,
  findings,
  cisControls,
  onSelectApi,
  onSelectFinding,
  onNavigateTab,
}: GlobalSearchModalProps) {
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
    }
  }, [isOpen]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const q = query.trim().toLowerCase();

  const filteredApis = q
    ? apis.filter(
        (a) =>
          a.name.toLowerCase().includes(q) ||
          a.baseUrl.toLowerCase().includes(q) ||
          a.environment.toLowerCase().includes(q)
      )
    : apis.slice(0, 3);

  const filteredFindings = q
    ? findings.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.findingId.toLowerCase().includes(q) ||
          f.endpoint.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
      )
    : findings.slice(0, 4);

  const filteredControls = q
    ? cisControls.filter(
        (c) =>
          c.title.toLowerCase().includes(q) ||
          c.controlId.toLowerCase().includes(q) ||
          c.category.toLowerCase().includes(q)
      )
    : cisControls.slice(0, 3);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 sm:p-6 pt-16 sm:pt-24 bg-slate-950/80 backdrop-blur-md">
      <div className="fixed inset-0" onClick={onClose} />
      <div className="relative w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden flex flex-col max-h-[80vh]">
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-slate-800 shrink-0">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            placeholder="Type a command or search APIs, findings, CIS controls..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
          />
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results Body */}
        <div className="p-4 overflow-y-auto space-y-5 text-left">
          {/* APIs Section */}
          {filteredApis.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span className="flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-cyan-400" />
                  APIs
                </span>
                <span>{filteredApis.length} results</span>
              </div>
              <div className="space-y-1">
                {filteredApis.map((api) => (
                  <button
                    key={api.id}
                    onClick={() => {
                      onSelectApi(api.id);
                      onClose();
                    }}
                    className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-800/80 hover:border-slate-700 transition group text-left"
                  >
                    <div>
                      <p className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                        {api.name}
                      </p>
                      <p className="text-[11px] font-mono text-slate-400">{api.baseUrl}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {api.environment}
                      </span>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Security Findings Section */}
          {filteredFindings.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  Security Findings
                </span>
                <span>{filteredFindings.length} results</span>
              </div>
              <div className="space-y-1">
                {filteredFindings.map((finding) => (
                  <button
                    key={finding.id}
                    onClick={() => {
                      onSelectFinding(finding.id);
                      onClose();
                    }}
                    className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-800/80 hover:border-slate-700 transition group text-left"
                  >
                    <div className="min-w-0 pr-3">
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono font-bold text-cyan-400">
                          {finding.findingId}
                        </span>
                        <p className="text-xs font-semibold text-slate-200 truncate group-hover:text-rose-300">
                          {finding.title}
                        </p>
                      </div>
                      <p className="text-[11px] font-mono text-slate-400 mt-0.5 truncate">
                        {finding.endpoint} • {finding.apiName}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityBadge severity={finding.severity} size="sm" />
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-rose-400" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* CIS Controls Section */}
          {filteredControls.length > 0 && (
            <div>
              <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2 px-1">
                <span className="flex items-center gap-1.5">
                  <FileCheck2 className="w-3.5 h-3.5 text-emerald-400" />
                  CIS Controls
                </span>
                <span>{filteredControls.length} results</span>
              </div>
              <div className="space-y-1">
                {filteredControls.map((control) => (
                  <button
                    key={control.id}
                    onClick={() => {
                      onNavigateTab('compliance');
                      onClose();
                    }}
                    className="w-full flex items-center justify-between p-2.5 rounded-lg border border-slate-800/80 bg-slate-900/40 hover:bg-slate-800/80 hover:border-slate-700 transition group text-left"
                  >
                    <div className="min-w-0 pr-3">
                      <p className="text-xs font-semibold text-slate-200 truncate group-hover:text-emerald-300">
                        <span className="font-mono text-emerald-400 mr-1.5">{control.controlId}:</span>
                        {control.title}
                      </p>
                      <p className="text-[11px] text-slate-400 mt-0.5 truncate">{control.category}</p>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <StatusBadge status={control.status} size="sm" />
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400" />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {filteredApis.length === 0 && filteredFindings.length === 0 && filteredControls.length === 0 && (
            <div className="py-12 text-center text-slate-500 text-sm">
              No matching security entities found for "{query}"
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
