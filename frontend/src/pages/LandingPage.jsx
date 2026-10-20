import React from 'react';
import { Link } from 'react-router-dom';

const STEPS = [
  { title: 'Collect signals', text: 'Device fingerprint, IP geolocation, impossible travel and request timing are attached to every sensitive action.' },
  { title: 'Score the risk', text: 'An additive, explainable score compares the action with the user\u2019s own baseline and recent sequence.' },
  { title: 'Decide by policy', text: 'Versioned policy-as-code maps risk and action sensitivity to one of five ordered responses.' },
  { title: 'Enforce and explain', text: 'Middleware applies the decision before the route runs and explains it to the user and the administrator.' }
];

const TIERS = [
  { name: 'allow', cls: 'bg-emerald-500/15 text-emerald-300 border-emerald-400/40' },
  { name: 'monitor', cls: 'bg-sky-500/15 text-sky-300 border-sky-400/40' },
  { name: 'reverify', cls: 'bg-amber-500/15 text-amber-300 border-amber-400/40' },
  { name: 'delay', cls: 'bg-orange-500/15 text-orange-300 border-orange-400/40' },
  { name: 'block', cls: 'bg-red-500/15 text-red-300 border-red-400/40' }
];

const SIGNALS = [
  { label: 'Device', pos: 'top-6 left-2', delay: '0s' },
  { label: 'Geo-IP', pos: 'top-24 right-0', delay: '0.8s' },
  { label: 'Travel', pos: 'bottom-24 left-0', delay: '1.6s' },
  { label: 'Baseline', pos: 'bottom-6 right-4', delay: '2.4s' }
];

/**
 * Public landing page (/). Entry point before login, signup or the admin console.
 * Motion is pure CSS and is disabled for users who prefer reduced motion.
 */
export function LandingPage() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 overflow-x-hidden" data-testid="landing-page">
      <style>{`
        @keyframes ag-pulse { 0% { transform: scale(0.6); opacity: 0.7; } 100% { transform: scale(1.6); opacity: 0; } }
        @keyframes ag-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
        @keyframes ag-rise { from { opacity: 0; transform: translateY(18px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes ag-flow { from { stroke-dashoffset: 24; } to { stroke-dashoffset: 0; } }
        @keyframes ag-glow { 0%, 100% { opacity: 0.35; } 50% { opacity: 0.7; } }
        .ag-ring { animation: ag-pulse 3.6s ease-out infinite; transform-origin: center; transform-box: fill-box; }
        .ag-float { animation: ag-float 5s ease-in-out infinite; }
        .ag-rise { animation: ag-rise 0.8s ease-out both; }
        .ag-flow { stroke-dasharray: 6 6; animation: ag-flow 1.2s linear infinite; }
        .ag-glow { animation: ag-glow 6s ease-in-out infinite; }
        @media (prefers-reduced-motion: reduce) {
          .ag-ring, .ag-float, .ag-rise, .ag-flow, .ag-glow { animation: none !important; }
        }
      `}</style>

      <header className="max-w-6xl mx-auto px-6 py-5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-white">AG</div>
          <span className="font-semibold tracking-tight">ActionGuard</span>
        </div>
        <nav className="flex items-center gap-3 text-sm">
          <Link to="/admin/login" className="text-slate-400 hover:text-white" data-testid="nav-admin">Admin</Link>
          <Link to="/login" className="px-3 py-1.5 rounded-lg border border-slate-700 hover:border-slate-500" data-testid="nav-login">Sign in</Link>
        </nav>
      </header>

      <section className="relative max-w-6xl mx-auto px-6 pt-10 pb-20 grid md:grid-cols-2 gap-10 items-center">
        <div className="absolute -top-10 left-1/2 -translate-x-1/2 h-72 w-72 rounded-full bg-indigo-600/30 blur-3xl ag-glow" aria-hidden="true" />
        <div className="relative ag-rise">
          <p className="text-xs uppercase tracking-widest text-indigo-300">Zero Trust after login</p>
          <h1 className="mt-3 text-4xl sm:text-5xl font-extrabold leading-tight" data-testid="landing-title">
            Never trust a session. Verify every action.
          </h1>
          <p className="mt-5 text-slate-300 max-w-md">
            ActionGuard scores the risk of each sensitive action in real time and responds in proportion:
            quiet for normal activity, firm when signals combine. Open source, self-hosted and explainable.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/signup" className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 font-medium shadow-lg shadow-indigo-900/40" data-testid="cta-signup">
              Get started
            </Link>
            <Link to="/login" className="px-5 py-2.5 rounded-lg border border-slate-600 hover:border-slate-400 font-medium" data-testid="cta-login">
              Sign in
            </Link>
          </div>
        </div>

        <div className="relative h-80 sm:h-96" aria-hidden="true">
          <svg viewBox="0 0 320 320" className="absolute inset-0 m-auto h-full w-full max-w-sm">
            {[0, 1.2, 2.4].map((d) => (
              <circle key={d} cx="160" cy="160" r="70" fill="none" stroke="#6366f1" strokeWidth="1.5" className="ag-ring" style={{ animationDelay: `${d}s` }} />
            ))}
            <path d="M160 70 L235 100 V165 C235 215 200 245 160 262 C120 245 85 215 85 165 V100 Z" fill="#1e1b4b" stroke="#818cf8" strokeWidth="3" />
            <circle cx="160" cy="150" r="26" fill="none" stroke="#a5b4fc" strokeWidth="3" />
            <circle cx="160" cy="150" r="10" fill="#c7d2fe" />
            <path className="ag-flow" d="M160 176 V232" stroke="#818cf8" strokeWidth="2.5" fill="none" />
          </svg>
          {SIGNALS.map((s) => (
            <span
              key={s.label}
              className={`absolute ${s.pos} ag-float px-3 py-1 rounded-full text-xs border border-indigo-400/40 bg-slate-900/80 text-indigo-200`}
              style={{ animationDelay: s.delay }}
            >
              {s.label}
            </span>
          ))}
        </div>
      </section>

      <section className="max-w-6xl mx-auto px-6 pb-20">
        <h2 className="text-2xl font-bold">How it works</h2>
        <div className="mt-8 grid sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {STEPS.map((step, i) => (
            <div key={step.title} className="ag-rise rounded-xl border border-slate-800 bg-slate-900/60 p-5" style={{ animationDelay: `${i * 0.12}s` }}>
              <div className="h-8 w-8 rounded-full bg-indigo-600/20 text-indigo-300 flex items-center justify-center text-sm font-semibold">{i + 1}</div>
              <h3 className="mt-3 font-semibold">{step.title}</h3>
              <p className="mt-2 text-sm text-slate-400">{step.text}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="max-w-6xl mx-auto px-6 pb-20">
        <h2 className="text-2xl font-bold">Five ordered responses</h2>
        <p className="mt-2 text-sm text-slate-400">Graded friction: the stronger the combined signals, the firmer the response.</p>
        <div className="mt-6 flex flex-wrap gap-3" data-testid="tier-list">
          {TIERS.map((t) => (
            <span key={t.name} className={`px-4 py-1.5 rounded-full border text-sm font-medium ${t.cls}`}>{t.name}</span>
          ))}
        </div>
      </section>

      <footer className="border-t border-slate-800 py-6 text-center text-xs text-slate-500">
        ActionGuard &middot; INSA Jimma Branch, 5th Cyber Talent Batch
      </footer>
    </div>
  );
}

export default LandingPage;
