import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, UserCheck, Code, Eye, EyeOff } from 'lucide-react';
import { Logo } from '../components/common/Logo';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

interface LoginPageProps {
  onNavigateRegister: () => void;
}

export function LoginPage({ onNavigateRegister }: LoginPageProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isForgotPasswordOpen, setIsForgotPasswordOpen] = useState(false);
  const [resetEmail, setResetEmail] = useState('');

  const { login } = useAuth();
  const { showToast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      showToast('Validation Error', 'Please provide email and password.', 'error');
      return;
    }

    try {
      setIsLoading(true);
      await login(email, password);
      showToast('Authentication Successful', 'Welcome back to ZENTRA Security Core.', 'success');
    } catch (err: any) {
      showToast('Authentication Failed', err.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDemoLogin = async (demoEmail: string) => {
    try {
      setIsLoading(true);
      await login(demoEmail, 'zentra2026!');
      showToast('Demo Access Granted', `Logged in as ${demoEmail}`, 'success');
    } catch (err: any) {
      showToast('Login Failed', err.message, 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = (e: React.FormEvent) => {
    e.preventDefault();
    showToast(
      'Reset Link Dispatched',
      `Zero-Trust recovery token dispatched to ${resetEmail}. Check your inbox.`,
      'info'
    );
    setIsForgotPasswordOpen(false);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Background Decorative Cyber Grid */}
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none" />
      <div className="absolute -top-40 -left-40 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute -bottom-40 -right-40 w-96 h-96 bg-blue-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="w-full max-w-md z-10 space-y-6">
        {/* Logo & Headline */}
        <div className="text-center space-y-2">
          <div className="flex justify-center">
            <Logo size="lg" />
          </div>
          <p className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
            AI-POWERED ZERO-TRUST API SECURITY ENGINE
          </p>
          <p className="text-xs text-slate-400">
            Enterprise boundary attestation, CIS benchmark compliance, and tamper-evident auditing.
          </p>
        </div>

        {/* Login Card */}
        <div className="p-6 sm:p-8 rounded-2xl bg-slate-900/80 border border-slate-800 backdrop-blur-xl shadow-2xl space-y-5">
          <form onSubmit={handleSubmit} className="space-y-4 text-left">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Corporate Email Address
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="email"
                  required
                  placeholder="name@organization.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-4 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-semibold text-slate-300">Password</label>
                <button
                  type="button"
                  onClick={() => setIsForgotPasswordOpen(true)}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 transition cursor-pointer"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-10 py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-500 hover:text-slate-300"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition disabled:opacity-50 cursor-pointer flex items-center justify-center gap-2"
            >
              <span>{isLoading ? 'Verifying Credentials...' : 'Sign In to ZENTRA'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Quick 1-Click Role Login Demo Bar */}
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <p className="text-[10px] font-mono uppercase tracking-wider text-slate-400 text-center">
              1-Click Demo Profiles (Pre-configured RBAC)
            </p>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleDemoLogin('admin@zentra.sec')}
                className="p-2 rounded-lg border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/40 text-cyan-300 text-[11px] font-mono transition text-center cursor-pointer flex flex-col items-center gap-1"
              >
                <Shield className="w-3.5 h-3.5" />
                <span>Admin</span>
              </button>

              <button
                type="button"
                onClick={() => handleDemoLogin('analyst@zentra.sec')}
                className="p-2 rounded-lg border border-purple-500/30 bg-purple-950/40 hover:bg-purple-900/40 text-purple-300 text-[11px] font-mono transition text-center cursor-pointer flex flex-col items-center gap-1"
              >
                <UserCheck className="w-3.5 h-3.5" />
                <span>Analyst</span>
              </button>

              <button
                type="button"
                onClick={() => handleDemoLogin('dev@zentra.sec')}
                className="p-2 rounded-lg border border-blue-500/30 bg-blue-950/40 hover:bg-blue-900/40 text-blue-300 text-[11px] font-mono transition text-center cursor-pointer flex flex-col items-center gap-1"
              >
                <Code className="w-3.5 h-3.5" />
                <span>Developer</span>
              </button>
            </div>
          </div>

          <div className="text-center pt-2">
            <p className="text-xs text-slate-400">
              Need an enterprise account?{' '}
              <button
                type="button"
                onClick={onNavigateRegister}
                className="text-cyan-400 hover:text-cyan-300 font-semibold transition cursor-pointer"
              >
                Register
              </button>
            </p>
          </div>
        </div>

        {/* Security Footer */}
        <p className="text-center text-[11px] font-mono text-slate-500">
          Zero-Trust Ingress Protection • SHA-256 Chained Telemetry
        </p>
      </div>

      {/* Forgot Password Modal */}
      {isForgotPasswordOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="w-full max-w-sm p-6 rounded-xl bg-slate-900 border border-slate-800 text-left space-y-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Reset Security Credentials</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Enter your registered corporate email to receive a single-use authorization token.
              </p>
            </div>
            <form onSubmit={handleResetPassword} className="space-y-3">
              <input
                type="email"
                required
                placeholder="name@organization.com"
                value={resetEmail}
                onChange={(e) => setResetEmail(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border border-slate-800 bg-slate-950 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsForgotPasswordOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-slate-800 text-xs text-slate-400 hover:text-slate-200"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white"
                >
                  Send Reset Token
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
