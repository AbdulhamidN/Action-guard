import React, { useEffect, useRef, useState } from 'react';
import { DECISION_ORDER, TIER_META } from './tiers.js';
import { useReducedMotion, usePointerGlow } from './hooks.js';

const CX = 200;
const CY = 180;

const NODES = [
  { label: 'GeoIP', x: 78, y: 64 },
  { label: 'Device Fingerprint', x: 322, y: 64 },
  { label: 'Impossible Travel', x: 78, y: 296 },
  { label: 'Behavioral Baseline', x: 322, y: 296 }
];

const SHIELD_PATH = 'M200 98 L268 124 V184 C268 224 238 250 200 266 C162 250 132 224 132 184 V124 Z';

/**
 * Hero visualization: four signal sources stream into a central shield whose
 * outline takes the color of the currently displayed response tier.
 * Pure SVG + CSS (jsdom safe). The tier readout below is real text in an
 * aria-live region; with reduced motion it is static and can be stepped manually.
 */
export function ShieldCanvas({ className = '' }) {
  const reduced = useReducedMotion();
  const wrapRef = useRef(null);
  const [index, setIndex] = useState(0);
  const [paused, setPaused] = useState(false);

  usePointerGlow(wrapRef, !reduced);

  useEffect(() => {
    if (reduced || paused) return undefined;
    const id = setInterval(() => setIndex((i) => (i + 1) % DECISION_ORDER.length), 3000);
    return () => clearInterval(id);
  }, [reduced, paused]);

  const tier = DECISION_ORDER[index];
  const meta = TIER_META[tier];
  const anim = (cls) => (reduced ? '' : cls);

  return (
    <div
      ref={wrapRef}
      className={`relative w-full max-w-md mx-auto ${className}`}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      style={{ '--mx': '50%', '--my': '40%' }}
      data-testid="shield-canvas"
    >
      <h2 className="sr-only">ActionGuard threat evaluation visualization</h2>

      <div
        className="pointer-events-none absolute inset-0 rounded-3xl"
        aria-hidden="true"
        style={{ background: 'radial-gradient(240px circle at var(--mx) var(--my), rgba(6,182,212,0.16), transparent 70%)' }}
      />

      <svg viewBox="0 0 400 340" className="relative w-full h-auto" aria-hidden="true" focusable="false">
        <defs>
          <radialGradient id="ag-core" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={meta.color} stopOpacity="0.9" />
            <stop offset="100%" stopColor={meta.color} stopOpacity="0" />
          </radialGradient>
          <linearGradient id="ag-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#6366F1" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#0B0F19" stopOpacity="0.2" />
          </linearGradient>
        </defs>

        {[0, 1.2, 2.4].map((d) => (
          <circle
            key={d}
            cx={CX}
            cy={CY}
            r="60"
            fill="none"
            stroke={meta.color}
            strokeWidth="1.5"
            className={anim('animate-ag-pulse')}
            style={{ transformBox: 'fill-box', transformOrigin: 'center', animationDelay: `${d}s`, opacity: reduced ? 0.25 : undefined }}
          />
        ))}

        <g className={anim('animate-ag-spin-slow')} style={{ transformOrigin: `${CX}px ${CY}px` }}>
          <circle cx={CX} cy={CY} r="112" fill="none" stroke="#6366F1" strokeOpacity="0.35" strokeDasharray="3 7" />
          <circle cx={CX} cy={CY - 112} r="4" fill="#06B6D4" />
          <circle cx={CX + 112} cy={CY} r="3" fill="#6366F1" />
          <circle cx={CX - 112} cy={CY} r="3" fill="#10B981" />
        </g>

        {NODES.map((n) => (
          <path
            key={n.label}
            d={`M${n.x} ${n.y} L${CX} ${CY}`}
            stroke="#06B6D4"
            strokeOpacity="0.7"
            strokeWidth="1.5"
            fill="none"
            strokeDasharray="6 6"
            className={anim('animate-ag-flow')}
          />
        ))}

        <path d={SHIELD_PATH} fill="url(#ag-fill)" stroke={meta.color} strokeWidth="3" style={{ transition: 'stroke 0.6s' }} />
        <path d="M200 124 L246 142 V184 C246 210 226 228 200 240 C174 228 154 210 154 184 V142 Z" fill="none" stroke="#06B6D4" strokeOpacity="0.45" strokeWidth="1.5" />
        <circle cx={CX} cy={CY} r="40" fill="url(#ag-core)" />
        <circle cx={CX} cy={CY} r="12" fill={meta.color} style={{ transition: 'fill 0.6s' }} />

        {NODES.map((n, i) => (
          <g key={`chip-${n.label}`} className={anim('animate-ag-float')} style={{ animationDelay: `${i * 0.7}s` }}>
            <rect x={n.x - 66} y={n.y - 15} width="132" height="30" rx="15" fill="#0F1424" stroke="#6366F1" strokeOpacity="0.6" />
            <text x={n.x} y={n.y + 4} textAnchor="middle" fontSize="11" fill="#E5E7EB">{n.label}</text>
          </g>
        ))}
      </svg>

      <div className="relative mt-2 rounded-xl border border-white/10 bg-white/[0.04] backdrop-blur-md px-4 py-3 text-center">
        <div className="flex items-center justify-center gap-2 text-[11px] uppercase tracking-widest text-ink-300">
          <span className={`inline-block h-2 w-2 rounded-full bg-state-ok ${anim('animate-ag-blink')}`} aria-hidden="true" />
          {reduced ? 'Static view' : paused ? 'Paused' : '\u25B6 Live'}
        </div>
        <p className="mt-1" aria-live="polite" data-testid="shield-readout">
          <span className="sr-only">Threat evaluation: </span>
          <span className="font-bold" style={{ color: meta.color }}>{meta.label}</span>
          <span className="sr-only"> tier</span>
        </p>
        <p className="text-xs text-ink-300">{meta.behavior}</p>
        {reduced && (
          <button
            type="button"
            onClick={() => setIndex((i) => (i + 1) % DECISION_ORDER.length)}
            className="mt-2 text-xs px-3 py-1 rounded-lg border border-white/15 hover:border-white/40"
          >
            Show next response tier
          </button>
        )}
      </div>
    </div>
  );
}

export default ShieldCanvas;
