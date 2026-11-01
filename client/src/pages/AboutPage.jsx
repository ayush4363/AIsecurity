import React from 'react';
import { Target, AlertTriangle, Settings, FileSearch, ShieldCheck, Lock, Activity, ArrowRight } from 'lucide-react';

export default function AboutPage({ onNavigate }) {
  const pillars = [
    {
      icon: FileSearch,
      title: 'Content Analysis',
      desc: 'Scans all incoming content for hidden instructions.',
    },
    {
      icon: ShieldCheck,
      title: 'Threat Detection',
      desc: 'Identifies prompt injection attempts and suspicious patterns.',
    },
    {
      icon: Lock,
      title: 'Action Control',
      desc: 'Prevents unauthorized actions and requires approval.',
    },
    {
      icon: Activity,
      title: 'Activity Monitoring',
      desc: 'Keeps a detailed record of every action performed.',
    },
  ];

  return (
    <div className="relative pt-6 pb-24 px-4 sm:px-8 max-w-7xl mx-auto text-left">
      {/* Hero Header with Ghost & Glowing Lantern (Exact match to screenshot 2 bottom-right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center mb-16">
        <div className="lg:col-span-7 space-y-6">
          <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/10 backdrop-blur-md border border-white/15 text-xs font-bold text-white shadow-sm">
            <span className="w-2 h-2 rounded-full bg-brand-yellow"></span>
            <span>OUR STORY</span>
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-white leading-[1.1]">
            Built for a <br />
            <span className="text-brand-yellow">safer digital tomorrow.</span>
          </h1>

          <p className="text-base sm:text-lg text-brand-cream/80 font-normal leading-relaxed max-w-xl">
            The Possessed Butler is an AI assistant designed to help you perform everyday digital tasks while protecting you from hidden malicious instructions, prompt injection attacks and other AI security risks.
          </p>

          <div className="pt-2">
            <button
              onClick={() => onNavigate('dashboard')}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-full text-sm font-bold bg-brand-yellow text-brand-darkText hover:bg-brand-yellowHover shadow-glow-yellow transition hover:scale-105"
            >
              <span>Explore The Butler Workspace</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Mascot sitting beside warm light/lantern */}
        <div className="lg:col-span-5 flex justify-center relative">
          <div className="relative w-72 sm:w-80">
            {/* Glow behind */}
            <div className="absolute inset-0 bg-brand-yellow/15 rounded-full blur-3xl pointer-events-none"></div>
            <div className="animate-float-slow">
              <img src="/mascot.png" alt="Ghost with Lantern" className="w-full h-auto drop-shadow-2xl" />
            </div>

            {/* Little glowing lantern simulation */}
            <div className="absolute -bottom-2 -left-4 p-3 rounded-2xl glass-panel-purple border border-brand-yellow/50 shadow-glow-yellow">
              <div className="w-6 h-6 rounded-lg bg-brand-yellow/80 animate-pulse flex items-center justify-center text-brand-darkText font-black text-xs">
                💡
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Story Cards (Mission, Problem, Approach - Cream Background) */}
      <div className="bg-[#FFF8EC] rounded-[36px] p-6 sm:p-10 border border-[#F3E2C2] shadow-xl text-brand-darkText space-y-10 mb-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Card 1: Our Mission */}
          <div className="bg-white rounded-3xl p-6 border border-[#EADBBA] shadow-sm space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-brand-primary/10 text-brand-primary flex items-center justify-center">
              <Target className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-black text-brand-darkText">Our Mission</h3>
            <p className="text-xs sm:text-sm text-[#5C4F74] font-medium leading-relaxed">
              To make AI assistance safe, reliable and trustworthy for everyone. We believe that AI can be incredibly helpful, but it must also be protected from manipulation and harmful instructions.
            </p>
          </div>

          {/* Card 2: The Problem */}
          <div className="bg-white rounded-3xl p-6 border border-[#EADBBA] shadow-sm space-y-4">
            <div className="w-12 h-12 rounded-2xl bg-red-100 text-red-600 flex items-center justify-center">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-black text-brand-darkText">The Problem</h3>
            <p className="text-xs sm:text-sm text-[#5C4F74] font-medium leading-relaxed">
              Hackers can hide malicious instructions inside emails, websites and documents. These instructions can trick AI agents into performing actions that you never intended, such as leaking private data or sending unauthorized emails.
            </p>
          </div>

          {/* Card 3: Our Approach */}
          <div className="bg-white rounded-3xl p-6 border border-[#EADBBA] shadow-sm space-y-4 md:col-span-2 lg:col-span-1">
            <div className="w-12 h-12 rounded-2xl bg-purple-100 text-brand-primary flex items-center justify-center">
              <Settings className="w-6 h-6" />
            </div>
            <h3 className="text-xl font-black text-brand-darkText">Our Approach</h3>
            <p className="text-xs sm:text-sm text-[#5C4F74] font-medium leading-relaxed">
              We combine powerful AI capabilities with a multi-layered security system to detect, block and prevent malicious instructions before they can harm you or execute arbitrary external actions.
            </p>
          </div>
        </div>

        {/* 4 Core Pillars Grid */}
        <div className="pt-6 border-t border-[#EDDCBC]">
          <h4 className="text-xs font-extrabold text-[#75688E] uppercase tracking-wider mb-6">
            Core Protective Architecture
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {pillars.map((p, idx) => {
              const Icon = p.icon;
              return (
                <div
                  key={idx}
                  className="bg-white rounded-2xl p-4 border border-[#EADBBA] shadow-sm flex items-start gap-3"
                >
                  <div className="w-9 h-9 rounded-xl bg-brand-primary/10 text-brand-primary flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className="w-4 h-4" />
                  </div>
                  <div>
                    <h5 className="font-extrabold text-sm text-brand-darkText">{p.title}</h5>
                    <p className="text-xs text-[#63557C] leading-relaxed mt-0.5">{p.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
