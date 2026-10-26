import React, { useState, useRef, useEffect } from 'react';
import {
  Search,
  Bell,
  Menu,
  PanelLeft,
  Shield,
  CheckCircle2,
  AlertTriangle,
  Lock,
  ChevronDown,
  LogOut,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { RoleType } from '../../types';
import { apiService } from '../../services/api';
import { MemoryToggle } from '../memory/MemoryToggle';

interface HeaderProps {
  onToggleSidebar?: () => void;
  onOpenMobileMenu?: () => void;
  onOpenSearch: () => void;
  onNavigateTab: (tab: string) => void;
}

export function Header({
  onToggleSidebar,
  onOpenMobileMenu,
  onOpenSearch,
  onNavigateTab,
}: HeaderProps) {
  const { user, role, switchRole, logout } = useAuth();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [aiMode, setAiMode] = useState<{ mode: string; label: string } | null>(null);
  const notificationRef = useRef<HTMLDivElement>(null);
  const profileRef = useRef<HTMLDivElement>(null);

  const notifications = [
    {
      id: 'n-1',
      title: 'Critical BOLA Vulnerability Detected',
      desc: 'User Management API endpoint /api/users/{id} requires object ownership check.',
      time: '12m ago',
      unread: true,
      severity: 'CRITICAL',
    },
    {
      id: 'n-2',
      title: 'SHA-256 Audit Chain Integrity Verified',
      desc: 'Automated cryptographic check verified 100% of audit ledger blocks.',
      time: '1h ago',
      unread: false,
      severity: 'INFO',
    },
    {
      id: 'n-3',
      title: 'Excessive JWT Lifetime Warning',
      desc: 'Auth service access token validity configured for 72h instead of 15m.',
      time: '3h ago',
      unread: false,
      severity: 'HIGH',
    },
  ];

  useEffect(() => {
    apiService.getAiStatus().then(setAiMode).catch(() => setAiMode(null));
  }, []);

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (notificationRef.current && !notificationRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) {
        setShowProfileMenu(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleToggle = onToggleSidebar || onOpenMobileMenu || (() => {});

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between h-16 px-4 sm:px-6 bg-slate-950 border-b border-slate-800/80">
      {/* Left: Sidebar Toggle & Global Search trigger */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleToggle}
          title="Toggle sidebar (N)"
          aria-label="Toggle sidebar (N)"
          className="flex items-center gap-1.5 p-2 -ml-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition"
        >
          <PanelLeft className="w-5 h-5 shrink-0" />
          <kbd className="hidden lg:inline-flex items-center justify-center text-[10px] font-mono text-slate-400 bg-slate-800/90 px-1.5 py-0.5 rounded border border-slate-700 leading-none">
            N
          </kbd>
        </button>

        <button
          onClick={onOpenSearch}
          className="flex items-center gap-3 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition w-48 sm:w-72 text-left"
        >
          <Search className="w-4 h-4 text-slate-400 shrink-0" />
          <span className="text-xs truncate">Search APIs, findings, CIS...</span>
          <kbd className="hidden sm:inline-block ml-auto text-[10px] font-mono text-slate-500 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700">
            ⌘K
          </kbd>
        </button>
      </div>

      {/* Right: Security Status, Notifications, Profile */}
      <div className="flex items-center gap-3">
        {/* Security Status Badges */}
        <div className="hidden md:flex items-center gap-2">
          <MemoryToggle onClick={() => onNavigateTab('memory')} />
          {aiMode && (
            <button
              onClick={() => onNavigateTab('settings')}
              title={`${aiMode.label} — Click to configure in Settings`}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[11px] font-mono transition cursor-pointer hover:opacity-90 active:scale-95 ${
                aiMode.mode === 'gemini'
                  ? 'border-purple-500/30 bg-purple-950/40 text-purple-300 hover:bg-purple-900/40'
                  : 'border-emerald-500/30 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/40'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{aiMode.mode === 'gemini' ? 'AI: Gemini + Offline' : 'OFFLINE MODE'}</span>
            </button>
          )}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-cyan-500/30 bg-cyan-950/40 text-[11px] font-mono text-cyan-300">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>TLS 1.3 / mTLS</span>
          </div>

          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-emerald-500/30 bg-emerald-950/40 text-[11px] font-mono text-emerald-300">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Audit Chain: 100% Verified</span>
          </div>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative" ref={notificationRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 transition"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl border border-slate-800 bg-slate-900 shadow-2xl p-4 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Security Notifications
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 border border-rose-500/40 text-rose-300">
                  1 Unread
                </span>
              </div>

              <div className="divide-y divide-slate-800/80 max-h-72 overflow-y-auto">
                {notifications.map((item) => (
                  <div key={item.id} className="py-2.5 flex items-start gap-2.5 text-left">
                    {item.severity === 'CRITICAL' ? (
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    ) : (
                      <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-slate-200">{item.title}</p>
                      <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">{item.desc}</p>
                      <span className="text-[10px] font-mono text-slate-500 mt-1 inline-block">
                        {item.time}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              <button
                onClick={() => {
                  setShowNotifications(false);
                  onNavigateTab('findings');
                }}
                className="w-full mt-3 py-1.5 text-center text-xs font-semibold text-cyan-400 hover:text-cyan-300 rounded bg-cyan-950/40 border border-cyan-500/30 transition"
              >
                View All Findings & Alerts
              </button>
            </div>
          )}
        </div>

        {/* User Profile / Quick Switcher */}
        <div className="relative" ref={profileRef}>
          <button
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2.5 p-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-900 transition"
          >
            <div className="w-7 h-7 rounded-md bg-gradient-to-tr from-cyan-600 to-blue-700 flex items-center justify-center text-xs font-bold text-white shadow-inner">
              {user?.name ? user.name[0].toUpperCase() : 'U'}
            </div>
            <div className="hidden sm:block text-left">
              <p className="text-xs font-semibold text-slate-200 leading-tight">{user?.name || 'User'}</p>
              <p className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
                {role}
              </p>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
          </button>

          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-64 rounded-xl border border-slate-800 bg-slate-900 shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
              <div className="pb-2.5 border-b border-slate-800">
                <p className="text-xs font-semibold text-slate-200">{user?.name}</p>
                <p className="text-[11px] text-slate-400 truncate">{user?.email}</p>
                <p className="text-[10px] font-mono text-cyan-400 mt-1">{user?.department}</p>
              </div>

              <div className="py-2 space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 px-2">
                  Switch Active Role:
                </span>
                {(['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'] as RoleType[]).map((r) => (
                  <button
                    key={r}
                    onClick={() => {
                      switchRole(r);
                      setShowProfileMenu(false);
                    }}
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded text-xs transition ${
                      role === r
                        ? 'bg-cyan-950/60 text-cyan-300 font-bold border border-cyan-500/30'
                        : 'text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    <span>{r.replace('_', ' ')}</span>
                    {role === r && <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />}
                  </button>
                ))}
              </div>

              <div className="pt-2 border-t border-slate-800">
                <button
                  onClick={() => {
                    setShowProfileMenu(false);
                    logout();
                  }}
                  className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-rose-400 hover:bg-rose-950/40 rounded transition"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
