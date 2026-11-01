import React from 'react';
import { Mail, Globe, FileText, Shield, Link2, CheckCircle2, BarChart3, Lock, Bell, ArrowRight } from 'lucide-react';
import HeroMascot from '../components/HeroMascot';

export default function FeaturesPage({ onNavigate }) {
  const featureList = [
    {
      id: 'email-analysis',
      icon: Mail,
      iconBg: 'bg-[#FFE52E]/25 text-[#9A7D0A]',
      title: 'Email Analysis',
      description: 'Read and summarize your emails, detect suspicious instructions and stay safe.',
      targetTab: 'email',
    },
    {
      id: 'secure-browsing',
      icon: Globe,
      iconBg: 'bg-[#3B82F6]/20 text-[#2563EB]',
      title: 'Secure Web Browsing',
      description: 'Visit websites and extract information without falling for hidden malicious prompts.',
      targetTab: 'browser',
    },
    {
      id: 'document-analysis',
      icon: FileText,
      iconBg: 'bg-[#8B5CF6]/20 text-[#7C3AED]',
      title: 'Document Analysis',
      description: 'Upload PDFs, DOCX and TXT files to get summaries and detect hidden instructions.',
      targetTab: 'documents',
    },
    {
      id: 'prompt-injection',
      icon: Shield,
      iconBg: 'bg-[#EF4444]/20 text-[#DC2626]',
      title: 'Prompt Injection Detection',
      description: 'Detect and block malicious instructions hidden in emails, websites and documents.',
      targetTab: 'playground',
    },
    {
      id: 'suspicious-links',
      icon: Link2,
      iconBg: 'bg-[#EC4899]/20 text-[#DB2777]',
      title: 'Suspicious Link Detection',
      description: 'Identify dangerous links and prevent the AI from visiting unsafe destinations.',
      targetTab: 'browser',
    },
    {
      id: 'safe-execution',
      icon: CheckCircle2,
      iconBg: 'bg-[#10B981]/20 text-[#059669]',
      title: 'Safe Task Execution',
      description: 'Perform useful tasks with your explicit approval and built-in security checks.',
      targetTab: 'overview',
    },
    {
      id: 'activity-monitoring',
      icon: BarChart3,
      iconBg: 'bg-[#F59E0B]/20 text-[#D97706]',
      title: 'Activity Monitoring',
      description: 'Keep track of every action the AI performs with detailed logs and reports.',
      targetTab: 'logs',
    },
    {
      id: 'permission-control',
      icon: Lock,
      iconBg: 'bg-[#6366F1]/20 text-[#4F46E5]',
      title: 'Permission Control',
      description: 'You decide what the AI can do with a secure permission system and approval workflow.',
      targetTab: 'approvals',
    },
    {
      id: 'realtime-alerts',
      icon: Bell,
      iconBg: 'bg-[#06B6D4]/20 text-[#0891B2]',
      title: 'Real-Time Security Alerts',
      description: 'Get notified immediately when suspicious activity is detected.',
      targetTab: 'alerts',
    },
  ];

  return (
    <div className="relative pt-6 pb-24 px-4 sm:px-8 max-w-7xl mx-auto text-left">
      {/* Hero Header */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center mb-16">
        <div className="lg:col-span-7 space-y-6">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/15 text-xs font-bold text-white shadow-sm">
            <span className="w-2 h-2 rounded-full bg-brand-yellow"></span>
            <span>POWERFUL FEATURES</span>
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white leading-[1.1]">
            Everything you need <br />
            for a <span className="text-brand-yellow">safer digital life.</span>
          </h1>

          <p className="text-base sm:text-lg text-brand-cream/80 font-normal leading-relaxed max-w-xl">
            Read, analyze, browse and perform tasks — safely. The Possessed Butler combines powerful AI capabilities with built-in security to protect you from hidden threats.
          </p>

          <div className="pt-2">
            <button
              onClick={() => onNavigate('dashboard')}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-full text-sm font-bold bg-brand-yellow text-brand-darkText hover:bg-brand-yellowHover shadow-glow-yellow transition hover:scale-105"
            >
              <span>Test Features in Live Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="lg:col-span-5 flex justify-center">
          <HeroMascot />
        </div>
      </div>

      {/* 9 Feature Cards Grid (Cream Style matching screenshot 2 top-left) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {featureList.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.id}
              onClick={() => onNavigate('dashboard')}
              className="group bg-[#FFF9EE] hover:bg-[#FFF4DC] p-6 rounded-[28px] border border-[#F3E3C6] shadow-card hover:shadow-xl transition-all duration-300 cursor-pointer transform hover:-translate-y-1.5 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className={`w-12 h-12 rounded-2xl ${item.iconBg} flex items-center justify-center`}>
                    <Icon className="w-6 h-6" />
                  </div>
                  <div className="w-8 h-8 rounded-full bg-white border border-[#E8D4B0] flex items-center justify-center text-brand-primary opacity-60 group-hover:opacity-100 group-hover:translate-x-0.5 transition-all">
                    <ArrowRight className="w-4 h-4" />
                  </div>
                </div>

                <h3 className="text-lg font-extrabold text-brand-darkText mb-2 tracking-tight group-hover:text-brand-primary transition-colors">
                  {item.title}
                </h3>
                <p className="text-xs sm:text-sm text-[#5B4F73] font-medium leading-relaxed">
                  {item.description}
                </p>
              </div>

              <div className="pt-5 mt-4 border-t border-[#F2DEB8] flex items-center justify-between text-[11px] font-bold text-brand-primary">
                <span>Try this tool</span>
                <span>Active Protection ✓</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
