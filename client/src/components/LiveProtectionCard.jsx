import React from 'react';
import { Shield, AlertCircle, Link2, CheckCircle2, Play } from 'lucide-react';

export default function LiveProtectionCard({ onOpenDemo }) {
  const protectionItems = [
    {
      id: 'prompt-injection',
      icon: Shield,
      label: 'Prompt Injection',
      status: 'Blocked',
      statusColor: 'bg-[#EF4444]/20 text-[#FCA5A5] border-[#EF4444]/40',
    },
    {
      id: 'malicious-content',
      icon: AlertCircle,
      label: 'Malicious Content',
      status: 'Blocked',
      statusColor: 'bg-[#EF4444]/20 text-[#FCA5A5] border-[#EF4444]/40',
    },
    {
      id: 'suspicious-links',
      icon: Link2,
      label: 'Suspicious Links',
      status: 'Blocked',
      statusColor: 'bg-[#EF4444]/20 text-[#FCA5A5] border-[#EF4444]/40',
    },
    {
      id: 'safe-actions',
      icon: CheckCircle2,
      label: 'Safe Actions',
      status: 'Allowed',
      statusColor: 'bg-[#22C55E]/20 text-[#86EFAC] border-[#22C55E]/40',
    },
  ];

  return (
    <div className="w-full max-w-[380px] space-y-4">
      {/* Upper Card: Live Protection Active */}
      <div className="glass-panel-purple rounded-[28px] p-6 border border-white/15 shadow-glow-purple">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-white/10">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-brand-yellow animate-ping"></span>
            <span className="w-2 h-2 rounded-full bg-brand-yellow -ml-3.5"></span>
            <span className="font-bold text-sm tracking-wide text-white">Live Protection</span>
          </div>
          <span className="text-xs font-extrabold text-brand-yellow tracking-wider uppercase">Active</span>
        </div>

        {/* Status Rows */}
        <div className="mt-4 space-y-3">
          {protectionItems.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.id}
                className="flex items-center justify-between p-2.5 rounded-2xl bg-white/5 hover:bg-white/10 transition-colors border border-white/5"
              >
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-xl bg-brand-primary/40 flex items-center justify-center text-white/90">
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-sm font-semibold text-white/95">{item.label}</span>
                </div>
                <span
                  className={`text-xs font-bold px-3 py-1 rounded-full border ${item.statusColor} shadow-sm`}
                >
                  {item.status}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Lower Card: Who's your AI Butler? */}
      <div className="glass-panel-purple rounded-[28px] p-4 sm:p-5 border border-white/15 shadow-glow-purple flex items-center justify-between gap-4">
        {/* Left: Ghost Avatar */}
        <div className="w-14 h-14 rounded-2xl bg-brand-primary/40 border border-white/20 p-1 flex-shrink-0 flex items-center justify-center overflow-hidden shadow-inner">
          <img src="/mascot.png" alt="Ghost Avatar" className="w-full h-full object-contain" />
        </div>

        {/* Center: Copy */}
        <div className="flex-1 text-left min-w-0">
          <h4 className="font-bold text-white text-sm sm:text-base tracking-tight truncate">
            Who's your AI Butler?
          </h4>
          <p className="text-xs text-brand-cream/70 leading-relaxed truncate">
            Meet the guardian of your digital world.
          </p>
        </div>

        {/* Right: Play Button */}
        <button
          onClick={onOpenDemo}
          className="w-10 h-10 rounded-full bg-brand-yellow hover:bg-brand-yellowHover text-brand-darkText flex items-center justify-center shadow-glow-yellow transition-transform hover:scale-110 flex-shrink-0"
          aria-label="Play Introduction Video"
        >
          <Play className="w-4 h-4 fill-brand-darkText ml-0.5" />
        </button>
      </div>
    </div>
  );
}
