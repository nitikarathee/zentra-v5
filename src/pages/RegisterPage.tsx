import React, { useState } from 'react';
import { Shield, Lock, Mail, User, ArrowRight, ArrowLeft } from 'lucide-react';
import { Logo } from '../components/common/Logo';
import { RoleType } from '../types';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

interface RegisterPageProps {
  onNavigateLogin: () => void;
}

export function RegisterPage({ onNavigateLogin }: RegisterPageProps) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<RoleType>('DEVELOPER');
  const [isLoading, setIsLoading] = useState(false);

  const { register } = useAuth();
  const { showToast } = useToast();

  const getPasswordStrength = () => {
    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  };

  const strength = getPasswordStrength();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (strength < 2) {
      showToast('Weak Password', 'Zero-Trust policy requires at least 8 characters with numbers or symbols.', 'warning');
      return;
    }

    try {
      setIsLoading(true);
      await register(name, email, password, role);
      showToast('Account Initialized', 'Welcome to ZENTRA Security Core.', 'success');
    } catch (err: any) {
      showToast('Registration Error', err.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden">
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md z-10 space-y-6">
        {/* Logo & Headline */}
        <div className="text-center space-y-2">
          <div className="flex justify-center">
            <Logo size="lg" />
          </div>
          <h2 className="text-lg font-bold text-slate-100">Provision Security Profile</h2>
          <p className="text-xs text-slate-400">
            Initialize an authenticated operator identity with role-based access entitlements.
          </p>
        </div>

        {/* Form Card */}
        <div className="p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl shadow-2xl space-y-4 text-left">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="text"
                  required
                  placeholder="Alex Vance"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Corporate Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="email"
                  required
                  placeholder="name@organization.sec"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Security Role Assignment
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as RoleType)}
                className="w-full px-3 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="DEVELOPER">DEVELOPER (Inventory, Scans, Remediation)</option>
                <option value="SECURITY_ANALYST">SECURITY_ANALYST (Findings, Compliance, AI, Reports)</option>
                <option value="ADMIN">ADMIN (Full Governance, Audits & RBAC Matrix)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Password
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>

              {/* Password Strength Indicator */}
              {password && (
                <div className="mt-2 space-y-1">
                  <div className="flex gap-1 h-1">
                    {[1, 2, 3, 4].map((level) => (
                      <div
                        key={level}
                        className={`flex-1 rounded-full transition-all duration-300 ${
                          strength >= level
                            ? strength <= 2
                              ? 'bg-rose-500'
                              : strength === 3
                              ? 'bg-amber-500'
                              : 'bg-emerald-500'
                            : 'bg-slate-800'
                        }`}
                      />
                    ))}
                  </div>
                  <p className="text-[10px] text-slate-500 font-mono text-right">
                    {strength <= 1 ? 'Too Weak' : strength === 2 ? 'Fair' : strength === 3 ? 'Strong' : 'Zero-Trust Secure'}
                  </p>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
            >
              <span>{isLoading ? 'Creating Identity...' : 'Provision Operator Account'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          <div className="text-center pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onNavigateLogin}
              className="text-xs text-slate-400 hover:text-cyan-400 flex items-center justify-center gap-1.5 mx-auto transition cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Sign In</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
