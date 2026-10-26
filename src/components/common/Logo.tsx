import React from 'react';

interface LogoProps {
  className?: string;
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
}

export function Logo({ className = '', size = 'md', showText = true }: LogoProps) {
  const sizeMap = {
    sm: { icon: 'w-7 h-7', text: 'text-lg' },
    md: { icon: 'w-8 h-8', text: 'text-xl' },
    lg: { icon: 'w-10 h-10', text: 'text-2xl' },
  }[size];

  return (
    <div className={`flex items-center gap-3 select-none ${className}`}>
      <div className={`relative flex items-center justify-center shrink-0 ${sizeMap.icon}`}>
        <div className="absolute inset-0 rounded-lg bg-gradient-to-tr from-cyan-500/20 via-blue-600/20 to-emerald-500/20 blur-sm" />
        <svg
          viewBox="0 0 48 48"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full relative z-10"
        >
          {/* Geometric Zero-Trust Shield Outline */}
          <polygon
            points="24,3 44,12 44,28 24,45 4,28 4,12"
            stroke="url(#zentraGradient)"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="#090d16"
            fillOpacity="0.85"
          />
          {/* Inner Hexagonal Ring */}
          <polygon
            points="24,9 38,16 38,28 24,39 10,28 10,16"
            stroke="#0ea5e9"
            strokeWidth="1"
            strokeOpacity="0.35"
            strokeDasharray="2 2"
          />
          {/* Sharp Geometric Z Monogram */}
          <path
            d="M17 17 H31 L17 31 H31"
            stroke="url(#accentGradient)"
            strokeWidth="3.2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
          {/* Center Zero-Trust Verification Core */}
          <circle cx="24" cy="24" r="2" fill="#10b981" />
          
          <defs>
            <linearGradient id="zentraGradient" x1="4" y1="3" x2="44" y2="45" gradientUnits="userSpaceOnUse">
              <stop stopColor="#06b6d4" />
              <stop offset="0.5" stopColor="#3b82f6" />
              <stop offset="1" stopColor="#10b981" />
            </linearGradient>
            <linearGradient id="accentGradient" x1="17" y1="17" x2="31" y2="31" gradientUnits="userSpaceOnUse">
              <stop stopColor="#38bdf8" />
              <stop offset="1" stopColor="#34d399" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      {showText && (
        <div className="flex flex-col">
          <div className="flex items-center gap-1.5">
            <span className={`font-extrabold tracking-wider text-slate-100 font-mono ${sizeMap.text}`}>
              ZENTRA
            </span>
            <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
              NETSEC
            </span>
          </div>
          <span className="text-[10px] tracking-wide text-slate-400 font-medium -mt-1 hidden sm:block">
            Network Compliance Engine
          </span>
        </div>
      )}
    </div>
  );
}
