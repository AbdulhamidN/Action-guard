import React, { useState, useEffect, useRef } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';

const PLATFORM_ITEMS = [
  { label: 'Overview', to: '/platform#overview' },
  { label: 'How It Works', to: '/platform#how-it-works' },
  { label: 'Capabilities', to: '/platform#capabilities' },
  { label: 'Architecture', to: '/platform#architecture' }
];

const SOLUTIONS_ITEMS = [
  { label: 'Account Takeover Protection', to: '/solutions#account-takeover' },
  { label: 'Session Security', to: '/solutions#session-security' },
  { label: 'Adaptive Authorization', to: '/solutions#adaptive-authorization' }
];

const RESOURCES_ITEMS = [
  { label: 'Documentation Portal', to: '/docs' },
  { label: 'Quickstart & Docker', to: '/docs#installation-guide' },
  { label: 'Configuration Guide', to: '/docs#environment-configuration' },
  { label: 'API Reference', to: '/docs#api-overview' },
  { label: 'Policy-as-Code', to: '/docs#policy-authorization' },
  { label: 'GitHub Repository', to: 'https://github.com/AbdulhamidN/Action-guard', external: true }
];

const SIGNIN_ITEMS = [
  { label: 'User Login', to: '/login' },
  { label: 'Admin Login', to: '/admin/login', testId: 'nav-admin' }
];

/**
 * Sticky Public Navigation Bar with high-contrast luminous branding,
 * accessible dropdowns, mobile navigation drawer, and Zero Trust identity.
 */
export function PublicNavbar() {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState(/** @type {string | null} */ (null));
  const [isScrolled, setIsScrolled] = useState(false);
  const navRef = useRef(/** @type {HTMLElement | null} */ (null));

  // Detect scroll to enhance navbar background depth
  useEffect(() => {
    function handleScroll() {
      if (window.scrollY > 20) {
        setIsScrolled(true);
      } else {
        setIsScrolled(false);
      }
    }
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Close dropdowns on outside click or Escape
  useEffect(() => {
    function handleClickOutside(event) {
      if (navRef.current && !navRef.current.contains(event.target)) {
        setActiveDropdown(null);
      }
    }
    function handleKeyDown(event) {
      if (event.key === 'Escape') {
        setActiveDropdown(null);
        setMobileMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Close menus when route changes
  useEffect(() => {
    setActiveDropdown(null);
    setMobileMenuOpen(false);
  }, [location.pathname, location.hash]);

  const toggleDropdown = (name) => {
    setActiveDropdown((current) => (current === name ? null : name));
  };

  const isCurrentSection = (path) => {
    return location.pathname === path;
  };

  const handleAnchorClick = (e, to, external) => {
    if (external) return;
    if (to.includes('#')) {
      const [path, hash] = to.split('#');
      if (location.pathname === path) {
        e.preventDefault();
        const element = document.getElementById(hash);
        if (element) {
          element.scrollIntoView({ behavior: 'smooth' });
        }
      }
    }
    setActiveDropdown(null);
    setMobileMenuOpen(false);
  };

  return (
    <header
      ref={navRef}
      className={`sticky top-0 z-50 transition-all duration-300 ${
        isScrolled
          ? 'bg-space-950/95 backdrop-blur-xl border-b border-brand-luminous/25 shadow-[0_8px_32px_rgba(0,0,0,0.6)]'
          : 'bg-space-900/85 backdrop-blur-md border-b border-white/10 shadow-[0_4px_20px_rgba(0,0,0,0.4)]'
      }`}
      data-testid="public-navbar"
    >
      <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-18 py-2">
          {/* Logo & Brand */}
          <Link
            to="/"
            className="flex items-center gap-3 font-bold tracking-tight text-white group focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-cyan rounded-lg p-1"
          >
            <span className="h-9 w-9 rounded-xl bg-gradient-to-br from-brand-luminous via-brand-blue to-brand-cyan flex items-center justify-center text-sm font-extrabold shadow-lg shadow-brand-luminous/30 group-hover:scale-105 transition-transform" aria-hidden="true">
              AG
            </span>
            <span className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-ink-100 to-brand-cyan bg-clip-text text-transparent">
              ActionGuard
            </span>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1.5 text-sm font-medium text-ink-300" aria-label="Primary Navigation">
            {/* Home */}
            <NavLink
              to="/"
              className={({ isActive }) =>
                `px-3.5 py-2 rounded-lg transition-colors ${
                  isActive && !location.hash
                    ? 'text-brand-cyan font-bold bg-white/[0.06] shadow-sm'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`
              }
            >
              Home
            </NavLink>

            {/* Platform Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => toggleDropdown('platform')}
                onMouseEnter={() => setActiveDropdown('platform')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-colors focus:outline-none ${
                  isCurrentSection('/platform') || activeDropdown === 'platform'
                    ? 'text-white font-bold bg-white/[0.06]'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`}
                aria-expanded={activeDropdown === 'platform'}
                aria-haspopup="true"
              >
                <span>Platform</span>
                <svg className={`w-4 h-4 transition-transform duration-200 ${activeDropdown === 'platform' ? 'rotate-180 text-brand-cyan' : 'text-ink-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              <div
                onMouseLeave={() => setActiveDropdown(null)}
                className={`absolute left-0 mt-1 w-64 rounded-2xl bg-space-850/98 backdrop-blur-2xl border border-brand-luminous/30 shadow-2xl p-2 z-50 ring-1 ring-white/10 animate-ag-rise ${
                  activeDropdown === 'platform' ? 'block' : 'hidden'
                }`}
              >
                <div className="px-3 py-1.5 border-b border-white/5 mb-1 flex justify-between items-center">
                  <span className="text-[11px] uppercase tracking-wider text-brand-cyan font-bold font-mono">Platform</span>
                  <Link to="/platform" onClick={() => setActiveDropdown(null)} className="text-xs text-brand-luminous hover:underline">View All &rarr;</Link>
                </div>
                {PLATFORM_ITEMS.map((item) => (
                  <Link
                    key={item.label}
                    to={item.to}
                    onClick={(e) => handleAnchorClick(e, item.to, false)}
                    className="block px-3 py-2 rounded-xl text-sm font-medium text-ink-200 hover:text-white hover:bg-white/[0.08] transition-colors group"
                  >
                    <span className="group-hover:text-brand-cyan transition-colors">{item.label}</span>
                  </Link>
                ))}
              </div>
            </div>

            {/* Solutions Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => toggleDropdown('solutions')}
                onMouseEnter={() => setActiveDropdown('solutions')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-colors focus:outline-none ${
                  isCurrentSection('/solutions') || activeDropdown === 'solutions'
                    ? 'text-white font-bold bg-white/[0.06]'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`}
                aria-expanded={activeDropdown === 'solutions'}
                aria-haspopup="true"
              >
                <span>Solutions</span>
                <svg className={`w-4 h-4 transition-transform duration-200 ${activeDropdown === 'solutions' ? 'rotate-180 text-brand-cyan' : 'text-ink-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              <div
                onMouseLeave={() => setActiveDropdown(null)}
                className={`absolute left-0 mt-1 w-72 rounded-2xl bg-space-850/98 backdrop-blur-2xl border border-brand-luminous/30 shadow-2xl p-2 z-50 ring-1 ring-white/10 animate-ag-rise ${
                  activeDropdown === 'solutions' ? 'block' : 'hidden'
                }`}
              >
                <div className="px-3 py-1.5 border-b border-white/5 mb-1 flex justify-between items-center">
                  <span className="text-[11px] uppercase tracking-wider text-brand-cyan font-bold font-mono">Solutions</span>
                  <Link to="/solutions" onClick={() => setActiveDropdown(null)} className="text-xs text-brand-luminous hover:underline">Explore All &rarr;</Link>
                </div>
                {SOLUTIONS_ITEMS.map((item) => (
                  <Link
                    key={item.label}
                    to={item.to}
                    onClick={(e) => handleAnchorClick(e, item.to, false)}
                    className="block px-3 py-2 rounded-xl text-sm font-medium text-ink-200 hover:text-white hover:bg-white/[0.08] transition-colors group"
                  >
                    <span className="group-hover:text-brand-cyan transition-colors">{item.label}</span>
                  </Link>
                ))}
              </div>
            </div>

            {/* Resources Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => toggleDropdown('resources')}
                onMouseEnter={() => setActiveDropdown('resources')}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg transition-colors focus:outline-none ${
                  isCurrentSection('/docs') || activeDropdown === 'resources'
                    ? 'text-white font-bold bg-white/[0.06]'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`}
                aria-expanded={activeDropdown === 'resources'}
                aria-haspopup="true"
              >
                <span>Resources</span>
                <svg className={`w-4 h-4 transition-transform duration-200 ${activeDropdown === 'resources' ? 'rotate-180 text-brand-cyan' : 'text-ink-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              <div
                onMouseLeave={() => setActiveDropdown(null)}
                className={`absolute left-0 mt-1 w-64 rounded-2xl bg-space-850/98 backdrop-blur-2xl border border-brand-luminous/30 shadow-2xl p-2 z-50 ring-1 ring-white/10 animate-ag-rise ${
                  activeDropdown === 'resources' ? 'block' : 'hidden'
                }`}
              >
                <div className="px-3 py-1.5 border-b border-white/5 mb-1 flex justify-between items-center">
                  <span className="text-[11px] uppercase tracking-wider text-brand-cyan font-bold font-mono">Resources</span>
                  <Link to="/docs" onClick={() => setActiveDropdown(null)} className="text-xs text-brand-luminous hover:underline">All Docs &rarr;</Link>
                </div>
                {RESOURCES_ITEMS.map((item) =>
                  item.external ? (
                    <a
                      key={item.label}
                      href={item.to}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block px-3 py-2 rounded-xl text-sm font-medium text-ink-200 hover:text-white hover:bg-white/[0.08] transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <span className="group-hover:text-brand-cyan transition-colors">{item.label}</span>
                        <svg className="w-3.5 h-3.5 text-ink-400 group-hover:text-brand-cyan" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                      </div>
                    </a>
                  ) : (
                    <Link
                      key={item.label}
                      to={item.to}
                      onClick={(e) => handleAnchorClick(e, item.to, false)}
                      className="block px-3 py-2 rounded-xl text-sm font-medium text-ink-200 hover:text-white hover:bg-white/[0.08] transition-colors group"
                    >
                      <span className="group-hover:text-brand-cyan transition-colors">{item.label}</span>
                    </Link>
                  )
                )}
              </div>
            </div>

            {/* About */}
            <NavLink
              to="/about"
              className={({ isActive }) =>
                `px-3.5 py-2 rounded-lg transition-colors ${
                  isActive
                    ? 'text-brand-cyan font-bold bg-white/[0.06]'
                    : 'hover:text-white hover:bg-white/[0.04]'
                }`
              }
            >
              About
            </NavLink>
          </nav>

          {/* Right Action / Auth Buttons */}
          <div className="hidden lg:flex items-center gap-3.5">
            {/* Sign In Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => toggleDropdown('signin')}
                onMouseEnter={() => setActiveDropdown('signin')}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg border text-sm font-semibold transition-all ${
                  activeDropdown === 'signin'
                    ? 'border-brand-luminous/60 text-white bg-brand-luminous/15 shadow-[0_0_15px_rgba(37,141,235,0.3)]'
                    : 'border-white/15 text-ink-100 hover:border-brand-luminous/40 hover:bg-white/[0.04]'
                }`}
                aria-expanded={activeDropdown === 'signin'}
                aria-haspopup="true"
                data-testid="nav-signin-dropdown"
              >
                <span>Sign In</span>
                <svg className={`w-3.5 h-3.5 transition-transform duration-200 ${activeDropdown === 'signin' ? 'rotate-180 text-brand-cyan' : 'text-ink-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              <div
                onMouseLeave={() => setActiveDropdown(null)}
                className={`absolute right-0 mt-1 w-56 rounded-2xl bg-space-850/98 backdrop-blur-2xl border border-brand-luminous/30 shadow-2xl p-2 z-50 ring-1 ring-white/10 animate-ag-rise ${
                  activeDropdown === 'signin' ? 'block' : 'hidden'
                }`}
              >
                <div className="px-3 py-1.5 border-b border-white/5 mb-1">
                  <span className="text-[11px] uppercase tracking-wider text-ink-400 font-bold font-mono">Sign In</span>
                </div>
                {SIGNIN_ITEMS.map((item) => (
                  <Link
                    key={item.label}
                    to={item.to}
                    data-testid={item.testId}
                    onClick={() => setActiveDropdown(null)}
                    className="block px-3 py-2 rounded-xl text-sm font-medium text-ink-200 hover:text-white hover:bg-white/[0.08] transition-colors group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="group-hover:text-brand-cyan transition-colors">{item.label}</span>
                      <span className="text-xs text-ink-400 group-hover:text-brand-cyan">&rarr;</span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>

            {/* Get Started CTA */}
            <Link
              to="/signup"
              className="px-5 py-2 rounded-lg text-sm font-bold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/25 hover:brightness-110 hover:shadow-brand-luminous/40 transition-all focus:outline-none focus:ring-2 focus:ring-brand-cyan"
            >
              Get Started
            </Link>
          </div>

          {/* Mobile Menu Button */}
          <div className="lg:hidden flex items-center gap-2">
            <Link
              to="/login"
              className="px-3 py-1.5 rounded-lg border border-white/15 text-xs text-ink-100 font-medium"
            >
              Sign In
            </Link>
            <button
              type="button"
              className="p-2 rounded-lg border border-white/15 text-ink-300 hover:text-white hover:bg-white/[0.05] focus:outline-none focus:ring-2 focus:ring-brand-cyan"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileMenuOpen}
              onClick={() => setMobileMenuOpen((o) => !o)}
            >
              {mobileMenuOpen ? (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              ) : (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
                </svg>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Navigation Drawer */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-t border-white/10 bg-space-950/98 backdrop-blur-2xl px-5 pt-4 pb-8 space-y-4 max-h-[85vh] overflow-y-auto">
          <div className="space-y-1">
            <NavLink
              to="/"
              onClick={() => setMobileMenuOpen(false)}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-lg text-sm font-semibold ${
                  isActive && !location.hash ? 'text-brand-cyan bg-white/[0.06]' : 'text-ink-100 hover:bg-white/[0.04]'
                }`
              }
            >
              Home
            </NavLink>

            {/* Platform Sub-links */}
            <div className="pt-2">
              <div className="px-3 text-xs uppercase tracking-wider text-brand-cyan font-bold font-mono">Platform</div>
              <div className="mt-1 space-y-1 pl-2">
                {PLATFORM_ITEMS.map((item) => (
                  <Link
                    key={item.label}
                    to={item.to}
                    onClick={(e) => handleAnchorClick(e, item.to, false)}
                    className="block px-3 py-1.5 rounded-lg text-sm text-ink-300 hover:text-white hover:bg-white/[0.04]"
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>

            {/* Solutions Sub-links */}
            <div className="pt-2">
              <div className="px-3 text-xs uppercase tracking-wider text-brand-cyan font-bold font-mono">Solutions</div>
              <div className="mt-1 space-y-1 pl-2">
                {SOLUTIONS_ITEMS.map((item) => (
                  <Link
                    key={item.label}
                    to={item.to}
                    onClick={(e) => handleAnchorClick(e, item.to, false)}
                    className="block px-3 py-1.5 rounded-lg text-sm text-ink-300 hover:text-white hover:bg-white/[0.04]"
                  >
                    {item.label}
                  </Link>
                ))}
              </div>
            </div>

            {/* Resources Sub-links */}
            <div className="pt-2">
              <div className="px-3 text-xs uppercase tracking-wider text-brand-cyan font-bold font-mono">Resources</div>
              <div className="mt-1 space-y-1 pl-2">
                {RESOURCES_ITEMS.map((item) =>
                  item.external ? (
                    <a
                      key={item.label}
                      href={item.to}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block px-3 py-1.5 rounded-lg text-sm text-ink-300 hover:text-white hover:bg-white/[0.04]"
                    >
                      {item.label} &nearr;
                    </a>
                  ) : (
                    <Link
                      key={item.label}
                      to={item.to}
                      onClick={(e) => handleAnchorClick(e, item.to, false)}
                      className="block px-3 py-1.5 rounded-lg text-sm text-ink-300 hover:text-white hover:bg-white/[0.04]"
                    >
                      {item.label}
                    </Link>
                  )
                )}
              </div>
            </div>

            {/* About */}
            <div className="pt-2">
              <NavLink
                to="/about"
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `block px-3 py-2 rounded-lg text-sm font-semibold ${
                    isActive ? 'text-brand-cyan bg-white/[0.06]' : 'text-ink-100 hover:bg-white/[0.04]'
                  }`
                }
              >
                About ActionGuard
              </NavLink>
            </div>
          </div>

          {/* Mobile Auth Buttons */}
          <div className="pt-4 border-t border-white/10 space-y-2">
            <Link
              to="/login"
              onClick={() => setMobileMenuOpen(false)}
              className="block w-full text-center px-4 py-2.5 rounded-lg border border-white/20 text-sm font-semibold text-white hover:bg-white/[0.05]"
            >
              User Login
            </Link>
            <Link
              to="/admin/login"
              data-testid="mobile-nav-admin"
              onClick={() => setMobileMenuOpen(false)}
              className="block w-full text-center px-4 py-2.5 rounded-lg border border-red-500/30 text-sm font-semibold text-red-400 hover:bg-red-500/10"
            >
              Admin Operator Console
            </Link>
            <Link
              to="/signup"
              onClick={() => setMobileMenuOpen(false)}
              className="block w-full text-center px-4 py-2.5 rounded-lg font-bold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg"
            >
              Get Started
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}

export default PublicNavbar;