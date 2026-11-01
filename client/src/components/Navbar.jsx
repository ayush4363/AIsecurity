import React, { useState } from 'react';
import { Shield, Menu, X, ArrowRight } from 'lucide-react';

export default function Navbar({ currentPage, onNavigate, isLoggedIn, onLogout }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'home', label: 'Home' },
    { id: 'features', label: 'Features' },
    { id: 'how-it-works', label: 'How It Works' },
    { id: 'security', label: 'Security' },
    { id: 'about', label: 'About' },
  ];

  return (
    <header className="relative z-50 pt-5 px-4 sm:px-8 max-w-7xl mx-auto">
      <nav className="flex items-center justify-between">
        {/* Brand Logo */}
        <button
          onClick={() => onNavigate('home')}
          className="flex items-center gap-3 group text-left transition focus:outline-none"
        >
          <div className="w-9 h-9 rounded-full bg-brand-primary/40 border border-brand-lavender/30 flex items-center justify-center p-1 shadow-glow-purple group-hover:scale-105 transition-transform overflow-hidden">
            <img src="/mascot.png" alt="Butler Logo" className="w-full h-full object-contain" />
          </div>
          <span className="font-extrabold text-lg sm:text-xl tracking-tight text-white group-hover:text-brand-yellow transition-colors">
            The Possessed Butler
          </span>
        </button>

        {/* Center Pill Menu (Desktop) */}
        <div className="hidden md:flex items-center bg-white/5 backdrop-blur-md border border-white/10 rounded-full px-4 py-1.5 shadow-glass">
          {navItems.map((item) => {
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onNavigate(item.id)}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-brand-primary text-white shadow-md shadow-brand-primary/50'
                    : 'text-brand-cream/80 hover:text-white hover:bg-white/5'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>

        {/* Right CTA / Auth */}
        <div className="hidden md:flex items-center gap-3">
          {isLoggedIn ? (
            <>
              <button
                onClick={() => onNavigate('dashboard')}
                className="px-4 py-1.5 rounded-full text-sm font-semibold text-brand-yellow hover:bg-white/5 transition"
              >
                Dashboard
              </button>
              <button
                onClick={onLogout}
                className="px-4 py-1.5 rounded-full text-sm font-medium text-white/70 hover:text-white transition"
              >
                Logout
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => onNavigate('login')}
                className="px-5 py-2 rounded-full text-sm font-medium text-white/90 hover:text-white hover:bg-white/10 transition border border-white/15"
              >
                Login
              </button>
              <button
                onClick={() => onNavigate('signup')}
                className="group flex items-center gap-2 px-5 py-2 rounded-full text-sm font-bold bg-brand-yellow text-brand-darkText hover:bg-brand-yellowHover shadow-glow-yellow transition-all duration-200 hover:scale-[1.02]"
              >
                <span>Get Started</span>
                <ArrowRight className="w-4 h-4 transition-transform group-hover:translate-x-1" />
              </button>
            </>
          )}
        </div>

        {/* Mobile Menu Button */}
        <div className="md:hidden flex items-center gap-2">
          <button
            onClick={() => onNavigate('dashboard')}
            className="px-3 py-1.5 rounded-full text-xs font-bold bg-brand-yellow text-brand-darkText"
          >
            App
          </button>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-2 rounded-lg bg-white/10 text-white hover:bg-white/20 transition"
            aria-label="Toggle Navigation"
          >
            {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </nav>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="md:hidden mt-3 p-4 rounded-2xl glass-panel-purple border border-brand-lavender/30 space-y-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => {
                onNavigate(item.id);
                setMobileMenuOpen(false);
              }}
              className={`w-full text-left px-4 py-2 rounded-xl text-sm font-medium ${
                currentPage === item.id ? 'bg-brand-primary text-white font-bold' : 'text-brand-cream/90 hover:bg-white/10'
              }`}
            >
              {item.label}
            </button>
          ))}
          <div className="pt-2 border-t border-white/10 flex flex-col gap-2">
            <button
              onClick={() => {
                onNavigate('login');
                setMobileMenuOpen(false);
              }}
              className="w-full text-center py-2 rounded-xl text-sm font-medium text-white border border-white/20"
            >
              Login
            </button>
            <button
              onClick={() => {
                onNavigate('signup');
                setMobileMenuOpen(false);
              }}
              className="w-full text-center py-2 rounded-xl text-sm font-bold bg-brand-yellow text-brand-darkText"
            >
              Get Started
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
