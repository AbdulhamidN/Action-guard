import React from 'react';
import { Link } from 'react-router-dom';
import { AmbientBackground } from '../components/common/AmbientBackground.jsx';

/**
 * Fallback 404 Not Found page.
 */
export function NotFoundPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-space-950 text-ink-100 py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden">
      <AmbientBackground variant="subtle" />
      <div className="max-w-md w-full text-center space-y-6 bg-space-850/90 backdrop-blur-xl p-8 sm:p-10 rounded-2xl shadow-2xl border border-white/10 ring-1 ring-white/5 relative z-10">
        <div className="h-12 w-12 rounded-xl bg-gradient-to-br from-brand-luminous to-brand-cyan flex items-center justify-center text-white font-black text-xl shadow-lg shadow-brand-luminous/30 mx-auto">
          AG
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-white" data-testid="page-title">
          404 - Page Not Found
        </h1>
        <p className="text-sm text-ink-300 leading-relaxed">
          The requested ActionGuard route or security resource does not exist.
        </p>
        <div className="flex flex-wrap justify-center gap-3 pt-2">
          <Link
            to="/"
            className="inline-flex items-center px-5 py-2.5 rounded-xl text-sm font-bold text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 transition-all hover:scale-[1.02]"
          >
            Return to Homepage
          </Link>
          <Link
            to="/login"
            className="inline-flex items-center px-5 py-2.5 border border-white/20 rounded-xl text-sm font-medium text-white hover:bg-white/[0.08] hover:border-brand-luminous/50 transition-colors"
          >
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
}

export default NotFoundPage;
