import React from 'react';
import {
  LayoutDashboard,
  Server,
  Radar,
  ShieldAlert,
  ShieldCheck,
  FileCheck2,
  Sparkles,
  Wrench,
  FileText,
  History,
  Settings,
  KeyRound,
  ChevronRight,
  LogOut,
  UserCheck,
  Brain,
  Cpu,
  GraduationCap,
  BrainCircuit,
} from 'lucide-react';
import { Logo } from '../common/Logo';
import { useAuth } from '../../context/AuthContext';

export type NavItem =
  | 'dashboard'
  | 'devices'
  | 'compliance'
  | 'training'
  | 'reports'
  | 'verify'
  | 'remediation'
  | 'findings'
  | 'audit-logs'
  | 'settings'
  | 'knowledge-base'
  | 'memory';

interface SidebarProps {
  currentTab: NavItem;
  onSelectTab: (tab: NavItem) => void;
  openFindingsCount?: number;
  isDesktopOpen: boolean;
  isOpenMobile: boolean;
  overlay?: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  currentTab,
  onSelectTab,
  openFindingsCount = 0,
  isDesktopOpen,
  isOpenMobile,
  overlay = false,
  onCloseMobile,
}: SidebarProps) {
  const { user, role, switchRole, logout } = useAuth();

  const navLinks: Array<{
    id: NavItem;
    label: string;
    icon: React.ElementType;
    badge?: number | string;
    badgeColor?: string;
  }> = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    {
      id: 'devices',
      label: 'Network Devices',
      icon: Cpu,
      badge: 'Configs',
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40',
    },
    {
      id: 'compliance',
      label: 'Compliance Engine',
      icon: FileCheck2,
      badge: '4 Stds',
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40',
    },
    {
      id: 'training',
      label: 'Parser Training',
      icon: GraduationCap,
      badge: 'Rules',
      badgeColor: 'bg-amber-500/20 text-amber-300 border border-amber-500/40',
    },
    {
      id: 'reports',
      label: 'Audit Reports',
      icon: FileText,
      badge: 'PDF / ZIP',
      badgeColor: 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40',
    },
    { id: 'verify', label: 'Verify Report', icon: ShieldCheck },
    { id: 'remediation', label: 'Remediation', icon: Wrench },
    {
      id: 'findings',
      label: 'Security Findings',
      icon: ShieldAlert,
      badge: openFindingsCount > 0 ? openFindingsCount : undefined,
      badgeColor: 'bg-rose-500/20 text-rose-300 border border-rose-500/40',
    },
    { id: 'audit-logs', label: 'Audit Ledger', icon: History },
    { id: 'knowledge-base', label: 'Knowledge Base', icon: Brain },
    {
      id: 'memory',
      label: 'Memory',
      icon: BrainCircuit,
      badge: 'Hindsight',
      badgeColor: 'bg-fuchsia-500/20 text-fuchsia-300 border border-fuchsia-500/40',
    },
    { id: 'settings', label: 'Settings & RBAC', icon: Settings },
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenMobile && overlay && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 transition-opacity duration-300"
          style={{ backgroundColor: 'rgba(0,0,0,0.7)' }}
          aria-hidden="true"
        />
      )}

      <aside
        // Inline styles so hiding/showing works even on older browsers that can't run Tailwind v4 transforms
        style={{
          backgroundColor: '#020617',
          transform: isDesktopOpen ? 'translateX(0)' : 'translateX(-100%)',
          visibility: isDesktopOpen ? 'visible' : 'hidden',
          transition: 'transform 300ms ease-in-out, visibility 300ms',
        }}
        className="fixed inset-y-0 left-0 z-50 w-64 max-w-[85vw] flex flex-col border-r border-slate-800"
      >
        {/* Header Branding */}
        <div className="flex items-center justify-between px-5 h-16 border-b border-slate-800/80">
          <Logo size="sm" />
        </div>

        {/* Baseline Engine Status Banner */}
        <div className="px-4 py-3 bg-slate-900/40 border-b border-slate-800/60">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-300">
                Baseline Engine
              </span>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-500/30 px-1.5 py-0.5 rounded">
              ENFORCED
            </span>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
          {navLinks.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectTab(item.id);
                  onCloseMobile();
                }}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-500/15 via-blue-500/10 to-transparent text-cyan-200 border-l-2 border-cyan-400 shadow-[inset_0_0_12px_rgba(6,182,212,0.1)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                <div className="flex items-center gap-1.5">
                  {item.badge !== undefined && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        item.badgeColor || 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                  {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />}
                </div>
              </button>
            );
          })}
        </nav>

        {/* Role Quick Switcher and User Info */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-900/30 space-y-2.5">
          <div className="px-2 py-1 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
              Active Context:
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => switchRole('ADMIN')}
                title="Switch to Admin"
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition ${
                  role === 'ADMIN'
                    ? 'bg-rose-950/60 border-rose-500 text-rose-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                ADM
              </button>
              <button
                onClick={() => switchRole('SECURITY_ANALYST')}
                title="Switch to Security Analyst"
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition ${
                  role === 'SECURITY_ANALYST'
                    ? 'bg-cyan-950/60 border-cyan-500 text-cyan-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                ANA
              </button>
              <button
                onClick={() => switchRole('DEVELOPER')}
                title="Switch to Developer"
                className={`text-[10px] font-mono px-1.5 py-0.5 rounded border transition ${
                  role === 'DEVELOPER'
                    ? 'bg-emerald-950/60 border-emerald-500 text-emerald-300 font-bold'
                    : 'border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                DEV
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between px-2 py-1.5 rounded-lg bg-slate-900/70 border border-slate-800">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 text-cyan-400">
                <UserCheck className="w-3.5 h-3.5" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold text-slate-200 truncate">{user?.name || 'Security User'}</p>
                <p className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider truncate">
                  {role}
                </p>
              </div>
            </div>

            <button
              onClick={logout}
              title="Sign Out"
              className="text-slate-400 hover:text-rose-400 p-1.5 rounded hover:bg-slate-800 transition"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
}
