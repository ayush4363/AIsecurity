import React, { useState } from 'react';
import { Mail, Lock, ArrowRight, ShieldCheck, Sparkles } from 'lucide-react';
import { api } from '../services/api';

export default function LoginPage({ onNavigate, onLoginSuccess }) {
  const [email, setEmail] = useState('judge@hackathon.ai');
  const [password, setPassword] = useState('demo-password');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await api.login(email, password);
      if (res.success) {
        onLoginSuccess(res.user);
        onNavigate('dashboard');
      } else {
        setError(res.error || 'Login failed');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemo = () => {
    onLoginSuccess({
      id: 'usr-demo-judge',
      name: 'Hackathon Judge',
      email: 'judge@hackathon.ai',
      role: 'Security Auditor'
    });
    onNavigate('dashboard');
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md glass-panel-purple p-8 rounded-[36px] border border-white/20 shadow-glow-purple text-left space-y-6 relative overflow-hidden">
        {/* Glow */}
        <div className="absolute top-0 right-0 w-32 h-32 bg-brand-yellow/10 rounded-full blur-2xl pointer-events-none"></div>

        {/* Brand Header */}
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-brand-primary/40 border border-white/20 p-2 shadow-inner">
            <img src="/mascot.png" alt="Ghost Logo" className="w-full h-full object-contain" />
          </div>
          <div>
            <h2 className="text-2xl font-black text-white">Welcome Back</h2>
            <p className="text-xs text-brand-cream/70">Sign in to The Possessed Butler</p>
          </div>
        </div>

        {/* Quick Demo Button for Judges */}
        <button
          onClick={handleQuickDemo}
          className="w-full py-3 px-4 rounded-2xl bg-brand-yellow hover:bg-brand-yellowHover text-brand-darkText font-extrabold text-sm shadow-glow-yellow flex items-center justify-center gap-2 transition hover:scale-[1.02]"
        >
          <Sparkles className="w-4 h-4 fill-brand-darkText" />
          <span>One-Click Judge Demo Sign-In</span>
          <ArrowRight className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2 text-xs text-brand-cream/40 my-2">
          <div className="flex-1 h-px bg-white/10"></div>
          <span>or sign in with credentials</span>
          <div className="flex-1 h-px bg-white/10"></div>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-red-950/60 border border-red-500/40 text-red-200 text-xs">
            {error}
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleLogin} className="space-y-4">
          <div>
            <label className="block text-xs font-bold text-brand-cream/80 uppercase tracking-wider mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-white/50 absolute left-3.5 top-3.5" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-black/30 border border-white/15 text-white text-sm focus:outline-none focus:border-brand-yellow placeholder-white/30"
                placeholder="you@domain.com"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-brand-cream/80 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-white/50 absolute left-3.5 top-3.5" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-black/30 border border-white/15 text-white text-sm focus:outline-none focus:border-brand-yellow placeholder-white/30"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 rounded-xl bg-white/10 hover:bg-white/15 border border-white/20 text-white font-bold text-sm transition"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>

        <div className="text-center pt-2 text-xs text-brand-cream/70">
          <span>Don't have an account? </span>
          <button
            onClick={() => onNavigate('signup')}
            className="text-brand-yellow font-bold hover:underline"
          >
            Create one now
          </button>
        </div>

        <div className="pt-2 flex items-center justify-center gap-1.5 text-[11px] text-brand-secGreen font-bold">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Protected by Multi-Layer Injection Defense</span>
        </div>
      </div>
    </div>
  );
}
