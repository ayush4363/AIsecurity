import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import DemoVideoModal from './components/DemoVideoModal';
import HomePage from './pages/HomePage';
import FeaturesPage from './pages/FeaturesPage';
import HowItWorksPage from './pages/HowItWorksPage';
import SecurityPage from './pages/SecurityPage';
import AboutPage from './pages/AboutPage';
import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import DashboardPage from './pages/DashboardPage';

export default function App() {
  const [currentPage, setCurrentPage] = useState('home');
  const [demoModalOpen, setDemoModalOpen] = useState(false);
  const [user, setUser] = useState({
    id: 'usr-judge',
    name: 'Hackathon Judge',
    email: 'judge@hackathon.ai',
    role: 'Security Auditor'
  });

  const handleNavigate = (page) => {
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    setUser(null);
    setCurrentPage('home');
  };

  return (
    <div className="min-h-screen bg-brand-deep text-white font-sans antialiased selection:bg-brand-yellow selection:text-brand-darkText flex flex-col justify-between">
      {/* Background radial atmosphere */}
      <div className="fixed inset-0 pointer-events-none -z-10 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-[#3e197d] via-[#24104d] to-[#14082c]"></div>

      <div>
        {/* Navigation Bar */}
        <Navbar
          currentPage={currentPage}
          onNavigate={handleNavigate}
          isLoggedIn={!!user}
          onLogout={handleLogout}
        />

        {/* Dynamic Pages */}
        <main className="w-full">
          {currentPage === 'home' && (
            <HomePage
              onNavigate={handleNavigate}
              onOpenDemo={() => setDemoModalOpen(true)}
            />
          )}

          {currentPage === 'features' && (
            <FeaturesPage onNavigate={handleNavigate} />
          )}

          {currentPage === 'how-it-works' && (
            <HowItWorksPage onNavigate={handleNavigate} />
          )}

          {currentPage === 'security' && (
            <SecurityPage onNavigate={handleNavigate} />
          )}

          {currentPage === 'about' && (
            <AboutPage onNavigate={handleNavigate} />
          )}

          {currentPage === 'login' && (
            <LoginPage
              onNavigate={handleNavigate}
              onLoginSuccess={handleLoginSuccess}
            />
          )}

          {currentPage === 'signup' && (
            <SignupPage
              onNavigate={handleNavigate}
              onLoginSuccess={handleLoginSuccess}
            />
          )}

          {currentPage === 'dashboard' && (
            <DashboardPage
              user={user}
              onNavigate={handleNavigate}
            />
          )}
        </main>
      </div>

      {/* Global Interactive Demo Modal */}
      <DemoVideoModal
        isOpen={demoModalOpen}
        onClose={() => setDemoModalOpen(false)}
      />

      {/* Footer */}
      <Footer onNavigate={handleNavigate} />
    </div>
  );
}
