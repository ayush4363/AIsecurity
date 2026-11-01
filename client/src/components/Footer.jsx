import React from 'react';
import { Shield, Lock, Eye, CheckCircle } from 'lucide-react';

export default function Footer({ onNavigate }) {
  return (
    <footer className="relative bg-brand-deep border-t border-brand-lavender/20 pt-16 pb-12 px-4 sm:px-8 text-brand-cream/80">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-10 pb-12 border-b border-white/10">
        {/* Col 1: Brand */}
        <div className="space-y-4 md:col-span-1">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-brand-primary/50 border border-brand-lavender/30 flex items-center justify-center p-1.5 shadow-glow-purple">
              <img src="/mascot.png" alt="Ghost Logo" className="w-full h-full object-contain" />
            </div>
            <span className="font-extrabold text-xl text-white">The Possessed Butler</span>
          </div>
          <p className="text-sm text-brand-cream/70 leading-relaxed">
            Your AI Butler for a Safer Digital Life. Built with dual-stage prompt injection defenses, least-privilege security, and human-in-the-loop action verification.
          </p>
          <div className="flex items-center gap-2 text-xs text-brand-yellow font-semibold">
            <Shield className="w-4 h-4 fill-brand-yellow/20" />
            <span>Active Protection Matrix v2.0</span>
          </div>
        </div>

        {/* Col 2: Navigation */}
        <div className="space-y-3">
          <h5 className="font-bold text-white text-sm tracking-wider uppercase">Navigation</h5>
          <ul className="space-y-2 text-sm">
            <li>
              <button onClick={() => onNavigate('home')} className="hover:text-brand-yellow transition">
                Home
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('features')} className="hover:text-brand-yellow transition">
                Features
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('how-it-works')} className="hover:text-brand-yellow transition">
                How It Works
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('security')} className="hover:text-brand-yellow transition">
                Security Architecture
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('about')} className="hover:text-brand-yellow transition">
                About The Mission
              </button>
            </li>
          </ul>
        </div>

        {/* Col 3: Product & Workspaces */}
        <div className="space-y-3">
          <h5 className="font-bold text-white text-sm tracking-wider uppercase">Agent Workspaces</h5>
          <ul className="space-y-2 text-sm">
            <li>
              <button onClick={() => onNavigate('dashboard')} className="hover:text-brand-yellow transition">
                AI Task Assistant
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('dashboard')} className="hover:text-brand-yellow transition">
                Protected Email Reader
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('dashboard')} className="hover:text-brand-yellow transition">
                Secure Web Browser
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('dashboard')} className="hover:text-brand-yellow transition">
                Document Security Scanner
              </button>
            </li>
            <li>
              <button onClick={() => onNavigate('dashboard')} className="hover:text-brand-yellow transition">
                Live Threat Telemetry
              </button>
            </li>
          </ul>
        </div>

        {/* Col 4: Hackathon Security Pledge */}
        <div className="space-y-3 p-5 rounded-2xl glass-panel-purple border border-white/10">
          <div className="flex items-center gap-2 text-brand-yellow">
            <Lock className="w-4 h-4" />
            <h5 className="font-bold text-sm tracking-wide">Security Guarantee</h5>
          </div>
          <p className="text-xs text-brand-cream/80 leading-relaxed">
            All untrusted web, document, and email content is sandboxed before consumption. The AI Butler will never execute external tools or exfiltrate private credentials without explicit approval.
          </p>
          <div className="flex items-center gap-1.5 text-[11px] text-brand-secGreen font-bold">
            <CheckCircle className="w-3.5 h-3.5" />
            <span>Zero-Trust Execution Model</span>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto mt-8 flex flex-col sm:flex-row items-center justify-between text-xs text-brand-cream/50 gap-4">
        <p>© 2026 The Possessed Butler – Track 03 Hackathon Project. All rights reserved.</p>
        <p className="flex items-center gap-2">
          <span>Protected Against Indirect Prompt Injection</span>
          <span>•</span>
          <span className="text-brand-yellow">AI Safety Verified</span>
        </p>
      </div>
    </footer>
  );
}
