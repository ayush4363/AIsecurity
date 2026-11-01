import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Link2, Lock, Eye, CheckCircle2, ChevronDown, Activity, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export default function SecurityPage({ onNavigate }) {
  const [stats, setStats] = useState({
    threatsDetected: 0,
    promptInjections: 0,
    suspiciousLinks: 0,
    maliciousContent: 0,
    safeActionsAllowed: 0
  });
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [timeFilter, setTimeFilter] = useState('Last 7 days');

  useEffect(() => {
    fetchSecurityData();
  }, []);

  const fetchSecurityData = async () => {
    setLoading(true);
    try {
      const [statsData, eventsData] = await Promise.all([
        api.getSecurityStats(),
        api.getSecurityEvents()
      ]);
      if (statsData.success) setStats(statsData.stats);
      if (eventsData.success) setEvents(eventsData.events);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const securityCards = [
    {
      icon: Shield,
      title: 'Prompt Injection Protection',
      description: "Detects hidden instructions that try to override the AI's behavior.",
      badge: 'Dual-Stage Defense',
    },
    {
      icon: AlertTriangle,
      title: 'Malicious Content Detection',
      description: 'Identifies harmful or deceptive content in emails, websites and documents.',
      badge: 'Zero-Width & Obfuscation Scan',
    },
    {
      icon: Link2,
      title: 'Suspicious Link Analysis',
      description: 'Scans links for potential phishing, malware or unsafe destinations.',
      badge: 'Domain Reputation Filter',
    },
    {
      icon: Lock,
      title: 'Permission-Based Execution',
      description: 'Performs sensitive actions only with your explicit approval.',
      badge: 'Human-in-the-Loop Guard',
    },
  ];

  return (
    <div className="relative pt-6 pb-24 px-4 sm:px-8 max-w-7xl mx-auto text-left">
      {/* Header Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center mb-16">
        <div className="lg:col-span-7 space-y-6">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/15 text-xs font-bold text-white shadow-sm">
            <span className="w-2 h-2 rounded-full bg-brand-yellow"></span>
            <span>BUILT-IN PROTECTION</span>
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white leading-[1.1]">
            Advanced Security <br />
            for the <span className="text-brand-yellow">AI World.</span>
          </h1>

          <p className="text-base sm:text-lg text-brand-cream/80 font-normal leading-relaxed max-w-xl">
            The Possessed Butler detects and blocks hidden malicious instructions, suspicious links and harmful content before they can manipulate the AI or compromise your data.
          </p>

          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={() => onNavigate('dashboard')}
              className="px-6 py-3 rounded-full text-sm font-bold bg-brand-yellow text-brand-darkText hover:bg-brand-yellowHover shadow-glow-yellow transition"
            >
              Open Security Console
            </button>
            <button
              onClick={fetchSecurityData}
              className="p-3 rounded-full bg-white/10 hover:bg-white/20 text-white transition"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>

        {/* Center / Right Mascot with Floating Shield Badges (Snug next to mascot while keeping character clearly visible) */}
        <div className="lg:col-span-5 relative flex justify-center items-center py-6">
          <div className="relative w-72 sm:w-80">
            {/* Mascot Image */}
            <div className="animate-float-slow">
              <img src="/mascot.png" alt="Protected Mascot" className="w-full h-auto drop-shadow-2xl" />
            </div>

            {/* Glowing Shield badge (Snug beside the mascot's shoulder, clear of lower badges) */}
            <div className="absolute top-20 sm:top-24 -right-6 sm:-right-8 z-20">
              <div className="p-3 rounded-2xl glass-panel-purple border-2 border-brand-yellow/80 shadow-glow-yellow animate-pulse-glow">
                <Shield className="w-7 h-7 sm:w-8 sm:h-8 text-brand-yellow fill-brand-yellow/30" />
              </div>
            </div>

            {/* Left Badges (Just a little bit outward so face and eyes are clearly visible without leaving a huge gap) */}
            <div className="absolute top-8 sm:top-10 -left-12 sm:-left-16 space-y-2 z-20 pointer-events-auto">
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <Shield className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                <span>Prompt Injection</span>
              </div>
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                <span>Malicious Content</span>
              </div>
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <Link2 className="w-3.5 h-3.5 text-purple-300 flex-shrink-0" />
                <span>Suspicious Links</span>
              </div>
            </div>

            {/* Right Badges (Just a little bit outward so mascot body is clearly visible without being cut off) */}
            <div className="absolute bottom-6 sm:bottom-8 -right-12 sm:-right-16 space-y-2 z-20 pointer-events-auto">
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <Lock className="w-3.5 h-3.5 text-blue-400 flex-shrink-0" />
                <span>Permission Control</span>
              </div>
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <Eye className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
                <span>Real-Time Monitoring</span>
              </div>
              <div className="px-3 py-1.5 rounded-xl glass-panel-purple text-[11px] font-bold text-white flex items-center gap-1.5 shadow-md border border-white/10 hover:border-white/30 transition whitespace-nowrap">
                <CheckCircle2 className="w-3.5 h-3.5 text-brand-secGreen flex-shrink-0" />
                <span>Safe Execution</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4 Security Cards (Cream Style) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-16">
        {securityCards.map((c, idx) => {
          const Icon = c.icon;
          return (
            <div
              key={idx}
              className="bg-[#FFF9EE] p-6 rounded-[28px] border border-[#F3E3C6] shadow-card space-y-4 flex flex-col justify-between"
            >
              <div>
                <div className="w-12 h-12 rounded-2xl bg-brand-primary/10 text-brand-primary flex items-center justify-center mb-4">
                  <Icon className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-extrabold text-brand-darkText mb-2 tracking-tight">
                  {c.title}
                </h3>
                <p className="text-xs sm:text-sm text-[#5B4F73] font-medium leading-relaxed">
                  {c.description}
                </p>
              </div>
              <div className="pt-3 border-t border-[#F2DEB8] text-[11px] font-bold text-brand-primary">
                {c.badge}
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Security Monitoring Section (Exact match to Screenshot 2 bottom-left) */}
      <div className="bg-[#FFF8EC] rounded-[36px] p-6 sm:p-10 border border-[#F3E2C2] shadow-xl text-brand-darkText space-y-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-2xl sm:text-3xl font-black tracking-tight text-brand-darkText">
              Live Security Monitoring
            </h2>
            <p className="text-xs sm:text-sm text-[#665A7F] font-medium mt-1">
              Real-time detection of threats and suspicious activity across all AI workspaces.
            </p>
          </div>

          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-2xl bg-white border border-[#EADBBA] text-xs font-bold text-brand-darkText shadow-sm">
            <span>{timeFilter}</span>
            <ChevronDown className="w-4 h-4 text-brand-darkText/60" />
          </div>
        </div>

        {/* 4 Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Stat 1 */}
          <div className="bg-white rounded-2xl p-5 border border-[#EADBBA] shadow-sm flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs font-bold text-[#72648B]">Threats Detected</span>
              <div className="text-3xl font-black text-brand-darkText">{stats.threatsDetected}</div>
            </div>
            <div className="flex flex-col items-end">
              <div className="w-10 h-10 rounded-xl bg-red-50 text-red-600 flex items-center justify-center font-bold">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold text-red-500 mt-1">+12%</span>
            </div>
          </div>

          {/* Stat 2 */}
          <div className="bg-white rounded-2xl p-5 border border-[#EADBBA] shadow-sm flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs font-bold text-[#72648B]">Prompt Injections</span>
              <div className="text-3xl font-black text-brand-darkText">{stats.promptInjections}</div>
            </div>
            <div className="flex flex-col items-end">
              <div className="w-10 h-10 rounded-xl bg-purple-50 text-brand-primary flex items-center justify-center font-bold">
                <Shield className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold text-purple-600 mt-1">+25%</span>
            </div>
          </div>

          {/* Stat 3 */}
          <div className="bg-white rounded-2xl p-5 border border-[#EADBBA] shadow-sm flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs font-bold text-[#72648B]">Suspicious Links</span>
              <div className="text-3xl font-black text-brand-darkText">{stats.suspiciousLinks}</div>
            </div>
            <div className="flex flex-col items-end">
              <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center font-bold">
                <Link2 className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold text-blue-500 mt-1">-8%</span>
            </div>
          </div>

          {/* Stat 4 */}
          <div className="bg-white rounded-2xl p-5 border border-[#EADBBA] shadow-sm flex items-center justify-between">
            <div className="space-y-1">
              <span className="text-xs font-bold text-[#72648B]">Malicious Content</span>
              <div className="text-3xl font-black text-brand-darkText">{stats.maliciousContent}</div>
            </div>
            <div className="flex flex-col items-end">
              <div className="w-10 h-10 rounded-xl bg-amber-50 text-amber-600 flex items-center justify-center font-bold">
                <Activity className="w-5 h-5" />
              </div>
              <span className="text-[11px] font-bold text-amber-600 mt-1">+20%</span>
            </div>
          </div>
        </div>

        {/* Live Security Events Table */}
        <div className="bg-white rounded-2xl border border-[#EADBBA] shadow-sm overflow-hidden">
          <div className="p-4 bg-[#FFF9EE] border-b border-[#EADBBA] flex items-center justify-between">
            <h4 className="font-extrabold text-sm text-brand-darkText">Recent Intercepted Security Events</h4>
            <span className="text-xs font-semibold text-brand-primary">Live Protection Active</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#FAF3E3] text-[#6E6088] font-bold border-b border-[#EADBBA]">
                <tr>
                  <th className="p-3.5">Threat Type</th>
                  <th className="p-3.5">Source</th>
                  <th className="p-3.5">Target</th>
                  <th className="p-3.5">Severity</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5">Action Taken</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F2E5CE]">
                {events.map((evt) => (
                  <tr key={evt.id} className="hover:bg-[#FFFDF7] transition">
                    <td className="p-3.5 font-bold text-brand-darkText flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-red-500"></span>
                      {evt.threatType}
                    </td>
                    <td className="p-3.5 text-[#5A4D74]">{evt.source}</td>
                    <td className="p-3.5 font-mono text-[11px] text-[#473B5E] max-w-[180px] truncate">
                      {evt.target}
                    </td>
                    <td className="p-3.5">
                      <span
                        className={`px-2 py-0.5 rounded-full font-bold text-[10px] ${
                          evt.severity === 'CRITICAL'
                            ? 'bg-red-100 text-red-700'
                            : 'bg-amber-100 text-amber-700'
                        }`}
                      >
                        {evt.severity}
                      </span>
                    </td>
                    <td className="p-3.5">
                      <span
                        className={`px-2.5 py-0.5 rounded-full font-bold text-[10px] ${
                          evt.status === 'Blocked'
                            ? 'bg-red-50 text-red-600 border border-red-200'
                            : 'bg-green-50 text-green-600 border border-green-200'
                        }`}
                      >
                        {evt.status}
                      </span>
                    </td>
                    <td className="p-3.5 text-[#63557F] font-medium">{evt.actionTaken}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
