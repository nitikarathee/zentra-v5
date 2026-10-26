import React from 'react';
import { Severity, FindingStatus } from '../../types';

interface SeverityBadgeProps {
  severity: Severity | string;
  size?: 'sm' | 'md' | 'lg';
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const s = severity.toUpperCase();

  const sizeClasses = {
    sm: 'text-[10px] px-1.5 py-0.5 font-mono',
    md: 'text-xs px-2.5 py-0.5 font-mono font-medium',
    lg: 'text-sm px-3 py-1 font-mono font-semibold',
  }[size];

  if (s === 'CRITICAL') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-950/40 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.15)] ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
        CRITICAL
      </span>
    );
  }

  if (s === 'HIGH') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-orange-500/40 bg-orange-950/40 text-orange-300 shadow-[0_0_10px_rgba(249,115,22,0.12)] ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />
        HIGH
      </span>
    );
  }

  if (s === 'MEDIUM') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-950/40 text-amber-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
        MEDIUM
      </span>
    );
  }

  if (s === 'LOW') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
        LOW
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800/60 text-slate-300 ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      {s || 'INFO'}
    </span>
  );
}

interface StatusBadgeProps {
  status: FindingStatus | string;
  size?: 'sm' | 'md';
}

export function StatusBadge({ status, size = 'md' }: StatusBadgeProps) {
  const s = status.toUpperCase();

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 font-mono',
    md: 'text-xs px-2.5 py-0.5 font-mono font-medium',
  }[size];

  if (s === 'OPEN') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-rose-500/30 bg-rose-950/20 text-rose-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
        OPEN
      </span>
    );
  }

  if (s === 'IN_PROGRESS') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-blue-500/30 bg-blue-950/20 text-blue-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
        IN PROGRESS
      </span>
    );
  }

  if (s === 'RESOLVED') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        RESOLVED
      </span>
    );
  }

  if (s === 'ACCEPTED_RISK') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-purple-500/30 bg-purple-950/20 text-purple-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
        ACCEPTED RISK
      </span>
    );
  }

  if (s === 'PASS') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-950/30 text-emerald-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
        PASS
      </span>
    );
  }

  if (s === 'FAIL') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-950/30 text-rose-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
        FAIL
      </span>
    );
  }

  if (s === 'WARNING') {
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-md border border-amber-500/40 bg-amber-950/30 text-amber-300 ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
        WARNING
      </span>
    );
  }

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800/50 text-slate-300 ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
      {s}
    </span>
  );
}
