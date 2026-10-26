import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  headerBorder?: boolean;
}

export function Card({
  children,
  className = '',
  title,
  subtitle,
  action,
  headerBorder = true,
}: CardProps) {
  return (
    <div
      className={`rounded-xl border border-slate-800/80 bg-slate-900/60 backdrop-blur-md shadow-xl transition-all duration-150 ${className}`}
    >
      {(title || action) && (
        <div
          className={`flex items-center justify-between px-5 py-4 ${
            headerBorder ? 'border-b border-slate-800/80' : ''
          }`}
        >
          <div>
            {typeof title === 'string' ? (
              <h3 className="font-semibold text-slate-100 text-base tracking-tight">{title}</h3>
            ) : (
              title
            )}
            {subtitle && <p className="text-xs text-slate-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </div>
  );
}
