import React from 'react';
import { Link } from 'react-router-dom';

/**
 * Shared Public Footer with categorized sitemap, repository links,
 * and verified open-source licensing.
 */
export function PublicFooter() {
  return (
    <footer className="border-t border-white/10 bg-space-900/90 text-ink-300 transition-colors" data-testid="public-footer">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-14">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 lg:gap-12">
          {/* Brand & Purpose (spans 2 cols on md+) */}
          <div className="col-span-2">
            <Link to="/" className="flex items-center gap-2.5 font-bold tracking-tight text-white">
              <span className="h-8 w-8 rounded-lg bg-gradient-to-br from-neon-indigo to-neon-cyan flex items-center justify-center text-xs font-extrabold shadow-sm" aria-hidden="true">
                AG
              </span>
              <span className="text-base font-extrabold tracking-tight">ActionGuard</span>
            </Link>
            <p className="mt-3 text-sm text-ink-300 max-w-sm leading-relaxed">
              Open-source Zero Trust security platform designed for continuous session risk evaluation, account takeover containment, and adaptive per-action authorization.
            </p>
            <div className="mt-4 flex items-center gap-3">
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-white/[0.05] border border-white/10 text-ink-300">
                Apache-2.0 Open Source
              </span>
              <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-neon-cyan/10 border border-neon-cyan/30 text-neon-cyan">
                Self-Hostable
              </span>
            </div>
          </div>

          {/* Platform Column */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-ink-100 mb-3">Platform</h4>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/platform#overview" className="hover:text-white transition-colors">Overview</Link>
              </li>
              <li>
                <Link to="/platform#how-it-works" className="hover:text-white transition-colors">How It Works</Link>
              </li>
              <li>
                <Link to="/platform#capabilities" className="hover:text-white transition-colors">Capabilities</Link>
              </li>
              <li>
                <Link to="/platform#architecture" className="hover:text-white transition-colors">Architecture</Link>
              </li>
              <li>
                <Link to="/#inspector" className="hover:text-white transition-colors">Policy Simulator</Link>
              </li>
            </ul>
          </div>

          {/* Solutions Column */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-ink-100 mb-3">Solutions</h4>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/solutions#account-takeover" className="hover:text-white transition-colors">Account Takeover</Link>
              </li>
              <li>
                <Link to="/solutions#session-security" className="hover:text-white transition-colors">Session Security</Link>
              </li>
              <li>
                <Link to="/solutions#adaptive-authorization" className="hover:text-white transition-colors">Adaptive Authorization</Link>
              </li>
              <li>
                <Link to="/login" className="hover:text-white transition-colors">User Portal</Link>
              </li>
              <li>
                <Link to="/admin/login" className="hover:text-white transition-colors">Operator Console</Link>
              </li>
            </ul>
          </div>

          {/* Resources & Community Column */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-ink-100 mb-3">Resources</h4>
            <ul className="space-y-2 text-sm">
              <li>
                <Link to="/docs#documentation" className="hover:text-white transition-colors">Documentation</Link>
              </li>
              <li>
                <Link to="/docs#installation" className="hover:text-white transition-colors">Quickstart Guide</Link>
              </li>
              <li>
                <Link to="/docs#api-reference" className="hover:text-white transition-colors">API Contract</Link>
              </li>
              <li>
                <Link to="/about" className="hover:text-white transition-colors">About & Mission</Link>
              </li>
              <li>
                <a
                  href="https://github.com/AbdulhamidN/Action-guard"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-white transition-colors inline-flex items-center gap-1 text-neon-cyan"
                >
                  GitHub Repository &nearr;
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-12 pt-8 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-ink-500">
          <p>
            &copy; {new Date().getFullYear()} ActionGuard &middot; Group 2, INSA Summer Camp 2026. Released under the Apache-2.0 License.
          </p>
          <div className="flex items-center gap-4">
            <Link to="/docs" className="hover:text-ink-300">Docs</Link>
            <span>&middot;</span>
            <Link to="/about" className="hover:text-ink-300">About</Link>
            <span>&middot;</span>
            <a
              href="https://github.com/AbdulhamidN/Action-guard"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-ink-300"
            >
              Source Code
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default PublicFooter;