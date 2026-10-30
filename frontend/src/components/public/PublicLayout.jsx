import React, { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { PublicNavbar } from './PublicNavbar.jsx';
import { PublicFooter } from './PublicFooter.jsx';

/**
 * Common layout wrapper for public-facing pages.
 * Enforces consistent dark visual identity, sticky navigation,
 * smooth anchor scrolling, and semantic footer.
 *
 * @param {{ children: React.ReactNode }} props
 */
export function PublicLayout({ children }) {
  const { pathname, hash } = useLocation();

  // Scroll to hash anchor when arriving from external or cross-page links
  useEffect(() => {
    try {
      if (hash) {
        const id = hash.replace('#', '');
        const element = document.getElementById(id);
        if (element && typeof element.scrollIntoView === 'function') {
          const timer = setTimeout(() => {
            try {
              element.scrollIntoView({ behavior: 'smooth' });
            } catch (_) {
              // Ignore jsdom scrollIntoView not implemented
            }
          }, 80);
          return () => clearTimeout(timer);
        }
      } else if (typeof window !== 'undefined' && typeof window.scrollTo === 'function') {
        try {
          window.scrollTo(0, 0);
        } catch (_) {
          // Ignore jsdom scrollTo not implemented
        }
      }
    } catch (_) {
      // Safe fallback
    }
  }, [pathname, hash]);

  return (
    <div className="min-h-screen bg-space-900 text-ink-100 flex flex-col selection:bg-neon-cyan/25 selection:text-white">
      <PublicNavbar />
      <main className="flex-1 w-full">{children}</main>
      <PublicFooter />
    </div>
  );
}

export default PublicLayout;