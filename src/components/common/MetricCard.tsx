import React from 'react';
import { LucideIcon } from 'lucide-react';

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  change?: string;
  trend?: 'up' | 'down' | 'neutral';
  icon: LucideIcon;
  variant?: 'cyan' | 'emerald' | 'rose' | 'amber' | 'blue' | 'purple';
  onClick?: () => void;
}

export function MetricCard({
  title,
  value,
  subtitle,
  change,
  trend = 'neutral',
  icon: Icon,
  variant = 'cyan',
  onClick,
}: MetricCardProps) {
  const variantStyles = {
    cyan: {
      border: 'border-cyan-500/30 hover:border-cyan-500/50',
      glow: 'from-cyan-500/10 to-transparent',
      iconBg: 'bg-cyan-950/60 text-cyan-400 border border-cyan-500/30',
      valueColor: 'text-cyan-200',
    },
    emerald: {
      border: 'border-emerald-500/30 hover:border-emerald-500/50',
      glow: 'from-emerald-500/10 to-transparent',
      iconBg: 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30',
      valueColor: 'text-emerald-200',
    },
    rose: {
      border: 'border-rose-500/30 hover:border-rose-500/50',
      glow: 'from-rose-500/10 to-transparent',
      iconBg: 'bg-rose-950/60 text-rose-400 border border-rose-500/30',
      valueColor: 'text-rose-200',
    },
    amber: {
      border: 'border-amber-500/30 hover:border-amber-500/50',
      glow: 'from-amber-500/10 to-transparent',
      iconBg: 'bg-amber-950/60 text-amber-400 border border-amber-500/30',
      valueColor: 'text-amber-200',
    },
    blue: {
      border: 'border-blue-500/30 hover:border-blue-500/50',
      glow: 'from-blue-500/10 to-transparent',
      iconBg: 'bg-blue-950/60 text-blue-400 border border-blue-500/30',
      valueColor: 'text-blue-200',
    },
    purple: {
      border: 'border-purple-500/30 hover:border-purple-500/50',
      glow: 'from-purple-500/10 to-transparent',
      iconBg: 'bg-purple-950/60 text-purple-400 border border-purple-500/30',
      valueColor: 'text-purple-200',
    },
  }[variant];

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-xl border bg-slate-900/70 p-5 backdrop-blur-md transition-all duration-200 ${variantStyles.border} ${
        onClick ? 'cursor-pointer hover:scale-[1.01]' : ''
      }`}
    >
      <div className={`absolute top-0 right-0 w-36 h-36 bg-gradient-to-bl ${variantStyles.glow} rounded-full blur-2xl pointer-events-none -mr-10 -mt-10`} />

      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">{title}</p>
          <h4 className={`text-2xl sm:text-3xl font-bold font-mono tracking-tight mt-1.5 ${variantStyles.valueColor}`}>
            {value}
          </h4>
        </div>
        <div className={`p-2.5 rounded-lg ${variantStyles.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {(subtitle || change) && (
        <div className="flex items-center gap-2 mt-3 pt-3 border-t border-slate-800/80 text-xs">
          {change && (
            <span
              className={`font-semibold font-mono ${
                trend === 'up'
                  ? 'text-emerald-400'
                  : trend === 'down'
                  ? 'text-rose-400'
                  : 'text-slate-400'
              }`}
            >
              {change}
            </span>
          )}
          {subtitle && <span className="text-slate-400 truncate">{subtitle}</span>}
        </div>
      )}
    </div>
  );
}
