import React, { useState, useEffect } from 'react';
import { Mail, Globe, FileText, Shield, Sparkles, Send } from 'lucide-react';
import Ghost3DCanvas from './Ghost3DCanvas';

export default function HeroMascot() {
  const [badgeParallax, setBadgeParallax] = useState({ x: 0, y: 0 });

  useEffect(() => {
    let animId;
    const handleMouseMove = (e) => {
      const normX = (e.clientX - window.innerWidth / 2) / (window.innerWidth / 2);
      const normY = (e.clientY - window.innerHeight / 2) / (window.innerHeight / 2);

      cancelAnimationFrame(animId);
      animId = requestAnimationFrame(() => {
        setBadgeParallax({
          x: Math.max(-1, Math.min(1, normX)) * 20,
          y: Math.max(-1, Math.min(1, normY)) * 16,
        });
      });
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(animId);
    };
  }, []);

  return (
    <div className="relative flex items-center justify-center w-full max-w-[480px] lg:max-w-[540px] mx-auto py-6 select-none">
      {/* Background ambient radial glows */}
      <div className="absolute inset-0 bg-brand-primary/40 rounded-full blur-3xl pointer-events-none transform -translate-y-4"></div>
      <div className="absolute w-72 h-72 bg-brand-lavender/20 rounded-full blur-2xl pointer-events-none"></div>

      {/* 
        REAL 3D VOLUMETRIC MASCOT CHARACTER (Three.js WebGL)
        Organic spine curvature, true 3D head turning, skirt cloth waves, and breathing physics
      */}
      <div className="relative z-10 w-full flex flex-col items-center justify-center">
        <Ghost3DCanvas />

        {/* Soft shadow directly underneath the 3D mascot */}
        <div className="w-3/4 h-8 bg-brand-deeper/70 rounded-full blur-xl mx-auto -mt-10 pointer-events-none"></div>
      </div>

      {/* ========================================================
          FLOATING GLASS BADGES (Multi-layer 3D Parallax Depth)
         ======================================================== */}

      {/* Floating Badge 1: Top-Left Mail Icon */}
      <div
        className="absolute top-8 -left-2 sm:left-4 z-20 pointer-events-none transition-transform duration-200 ease-out"
        style={{
          transform: `translate3d(${badgeParallax.x * 1.3}px, ${badgeParallax.y * 1.3}px, 0)`,
        }}
      >
        <div className="w-16 h-16 sm:w-20 sm:h-20 rounded-3xl glass-panel-purple flex items-center justify-center p-3 shadow-glow-purple border border-white/20 transform -rotate-6 hover:rotate-0 transition duration-300 animate-float-subtle pointer-events-auto">
          <Mail className="w-8 h-8 sm:w-10 sm:h-10 text-white/90 drop-shadow" />
        </div>
      </div>

      {/* Floating Badge 2: Bottom-Left Browser Globe */}
      <div
        className="absolute bottom-16 -left-4 sm:left-6 z-20 pointer-events-none transition-transform duration-200 ease-out"
        style={{
          transform: `translate3d(${badgeParallax.x * 1.05}px, ${badgeParallax.y * 1.05}px, 0)`,
        }}
      >
        <div
          className="w-14 h-14 sm:w-16 sm:h-16 rounded-2xl glass-panel-purple flex items-center justify-center p-2.5 shadow-glow-purple border border-white/20 transform rotate-12 hover:rotate-0 transition duration-300 animate-float-subtle pointer-events-auto"
          style={{ animationDelay: '1.5s' }}
        >
          <Globe className="w-7 h-7 sm:w-8 sm:h-8 text-white/80" />
        </div>
      </div>

      {/* Floating Badge 3: Top-Right Document */}
      <div
        className="absolute top-10 -right-2 sm:right-6 z-20 pointer-events-none transition-transform duration-200 ease-out"
        style={{
          transform: `translate3d(${badgeParallax.x * 1.25}px, ${badgeParallax.y * 1.25}px, 0)`,
        }}
      >
        <div
          className="w-16 h-16 sm:w-18 sm:h-18 rounded-3xl glass-panel-purple flex items-center justify-center p-3 shadow-glow-purple border border-white/20 transform rotate-6 hover:rotate-0 transition duration-300 animate-float-subtle pointer-events-auto"
          style={{ animationDelay: '0.8s' }}
        >
          <FileText className="w-8 h-8 sm:w-9 sm:h-9 text-white/90" />
        </div>
      </div>

      {/* Floating Badge 4: Bottom-Right "Blocking Hidden Threats..." Card */}
      <div
        className="absolute bottom-14 -right-4 sm:right-0 z-20 pointer-events-none transition-transform duration-200 ease-out"
        style={{
          transform: `translate3d(${badgeParallax.x * 1.15}px, ${badgeParallax.y * 1.15}px, 0)`,
        }}
      >
        <div
          className="flex items-center gap-2.5 px-4 py-2.5 rounded-2xl glass-panel-purple border border-white/20 shadow-glow-purple backdrop-blur-xl animate-float-subtle pointer-events-auto"
          style={{ animationDelay: '2.2s' }}
        >
          <div className="w-8 h-8 rounded-xl bg-brand-yellow/20 border border-brand-yellow/40 flex items-center justify-center">
            <Shield className="w-5 h-5 text-brand-yellow fill-brand-yellow/30" />
          </div>
          <div className="text-left">
            <p className="text-[10px] text-white/60 font-medium tracking-wide uppercase">Active Guard</p>
            <p className="text-xs font-bold text-white tracking-tight">Blocking Hidden Threats...</p>
          </div>
        </div>
      </div>

      {/* Floating Golden Stars / Sparkles */}
      <div className="absolute top-2 left-1/3 text-brand-yellow animate-pulse-glow">
        <Sparkles className="w-5 h-5 fill-brand-yellow" />
      </div>

      <div
        className="absolute top-1/4 right-0 text-brand-yellow animate-pulse-glow"
        style={{ animationDelay: '1.2s' }}
      >
        <Sparkles className="w-6 h-6 fill-brand-yellow" />
      </div>

      <div
        className="absolute bottom-6 left-1/4 text-brand-yellow animate-pulse-glow"
        style={{ animationDelay: '2s' }}
      >
        <Sparkles className="w-5 h-5 fill-brand-yellow" />
      </div>

      {/* Floating yellow paper plane / arrow */}
      <div className="absolute bottom-10 right-28 text-brand-yellow transform rotate-45 animate-float-subtle">
        <Send className="w-4 h-4 fill-brand-yellow" />
      </div>
    </div>
  );
}
