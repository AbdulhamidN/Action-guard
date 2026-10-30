import React from 'react';
import { DECISION_ORDER, TIER_META } from './tiers.js';
import { ACTIONS } from './PolicyInspector.jsx';

const GAUGE_COLORS = {
  low: '#10B981',
  medium: '#F59E0B',
  high: '#F97316',
  critical: '#EF4444'
};

const RESPONSE_ICONS = {
  allow: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  monitor: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
  ),
  reverify: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
  ),
  delay: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  block: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
    </svg>
  )
};

/**
 * Animated Technology Background for the Visual Security Pipeline
 * Features moving gradient orbs, SVG connection grid, traveling data packets, and a scanning radar.
 */
export function PipelineBackground() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-3xl" aria-hidden="true">
      {/* Deep Navy Atmosphere */}
      <div className="absolute inset-0 bg-gradient-to-b from-[#0B1327]/90 via-[#101C38]/95 to-[#0B1327]/90" />

      {/* Ambient Luminous Orbs */}
      <div className="absolute -top-24 left-1/4 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-[#174A91]/30 via-[#258DEB]/20 to-transparent blur-[120px] animate-ag-aurora" />
      <div className="absolute -bottom-24 right-1/4 w-[450px] h-[450px] rounded-full bg-gradient-to-bl from-[#35C5E8]/20 via-[#258DEB]/15 to-transparent blur-[110px] animate-ag-float-reverse" />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] rounded-full bg-[#174A91]/15 blur-[130px] animate-ag-glow" />

      {/* Cyber Mesh Pattern */}
      <div className="absolute inset-0 ag-mesh-pattern opacity-40" />

      {/* Soft Top & Bottom Luminous Borders */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#35C5E8]/40 to-transparent" />
      <div className="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#258DEB]/30 to-transparent" />

      {/* SVG Animated Circuit & Node Grid */}
      <svg className="absolute inset-0 w-full h-full opacity-25" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="pipelineBeam" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#258DEB" stopOpacity="0.2" />
            <stop offset="50%" stopColor="#35C5E8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#258DEB" stopOpacity="0.2" />
          </linearGradient>
        </defs>
        {/* Animated Connecting Buslines */}
        <line x1="5%" y1="48%" x2="95%" y2="48%" stroke="url(#pipelineBeam)" strokeWidth="1" strokeDasharray="6 8" className="animate-ag-flow" />
        <line x1="20%" y1="20%" x2="50%" y2="48%" stroke="#35C5E8" strokeWidth="0.8" strokeDasharray="4 6" opacity="0.4" />
        <line x1="80%" y1="20%" x2="50%" y2="48%" stroke="#258DEB" strokeWidth="0.8" strokeDasharray="4 6" opacity="0.4" />
        {/* Circuit Nodes */}
        <circle cx="20%" cy="48%" r="3" fill="#35C5E8" />
        <circle cx="50%" cy="48%" r="4" fill="#35C5E8" />
        <circle cx="80%" cy="48%" r="3" fill="#258DEB" />
      </svg>
    </div>
  );
}

/**
 * 5-Stage Visual Security Flow Component
 * 01 - Context (Understand the session)
 * 02 - Risk Analysis (Evaluate changing signals)
 * 03 - Policy Decision (Evaluate every action)
 * 04 - Response (Allow, Monitor, Re-verify, Delay, Block)
 * 05 - Continuous Trust (Trust is continuously evaluated - animated loop back)
 */
export function VisualSecurityFlow({ inputs, result }) {
  const currentAction = ACTIONS.find((a) => a.id === inputs.action) || ACTIONS[0];
  const gaugeColor = GAUGE_COLORS[result.riskTier] || '#10B981';
  const tierMeta = TIER_META[result.decision];

  // Context Signals Visual State
  const deviceState = inputs.newDevice
    ? { label: 'Unrecognized Device', badge: '+25 Risk', tone: 'text-amber-400 border-amber-500/40 bg-amber-500/10' }
    : { label: 'Known Enrolled Device', badge: 'Normal', tone: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' };

  const locationState = inputs.impossibleTravel
    ? { label: 'Impossible Travel', badge: '+28 Critical', tone: 'text-red-400 border-red-500/50 bg-red-500/15' }
    : inputs.newCountry
    ? { label: 'New Country (GeoIP)', badge: '+25 Risk', tone: 'text-amber-400 border-amber-500/40 bg-amber-500/10' }
    : { label: 'Usual Geographic Zone', badge: 'Normal', tone: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' };

  const behaviorState = inputs.baselineDeviation
    ? { label: 'Deviates from Baseline', badge: '+13 Risk', tone: 'text-amber-400 border-amber-500/40 bg-amber-500/10' }
    : { label: 'Within 30-Day Baseline', badge: 'Normal', tone: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' };

  const timingState = inputs.timing === 'automation_burst'
    ? { label: 'Automation Burst', badge: '+20 Anomaly', tone: 'text-orange-400 border-orange-500/50 bg-orange-500/15' }
    : inputs.timing === 'unusual_hour'
    ? { label: 'Unusual Hour', badge: '+10 Anomaly', tone: 'text-amber-400 border-amber-500/40 bg-amber-500/10' }
    : { label: 'Typical Cadence', badge: 'Normal', tone: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' };

  return (
    <div className="relative rounded-3xl border border-white/10 bg-space-900/80 backdrop-blur-xl p-6 sm:p-8 shadow-2xl shadow-brand-blue/20 overflow-hidden">
      <PipelineBackground />

      <div className="relative z-10 space-y-10">
        {/* Stages 01 to 04 Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 items-stretch">
          
          {/* ======================================================== */}
          {/* STAGE 01 — CONTEXT */}
          {/* ======================================================== */}
          <div className="rounded-2xl border border-white/10 bg-space-850/60 p-5 flex flex-col justify-between hover:border-brand-luminous/40 transition-all">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <span className="text-[11px] font-mono font-bold tracking-wider text-brand-cyan uppercase">01 — CONTEXT</span>
                <span className="flex h-2 w-2 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand-cyan opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-brand-cyan"></span>
                </span>
              </div>
              <h3 className="mt-3 text-base font-bold text-white tracking-tight">Understand the session</h3>
              <p className="text-xs text-ink-300 mt-1">Continuous contextual signal telemetry.</p>

              {/* 4 Context Visual Nodes */}
              <div className="mt-4 space-y-2">
                <div className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center justify-between transition-colors ${deviceState.tone}`}>
                  <span className="font-medium truncate mr-2">Device: {deviceState.label}</span>
                  <span className="text-[10px] font-mono shrink-0 uppercase font-bold">{deviceState.badge}</span>
                </div>
                <div className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center justify-between transition-colors ${locationState.tone}`}>
                  <span className="font-medium truncate mr-2">Location: {locationState.label}</span>
                  <span className="text-[10px] font-mono shrink-0 uppercase font-bold">{locationState.badge}</span>
                </div>
                <div className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center justify-between transition-colors ${behaviorState.tone}`}>
                  <span className="font-medium truncate mr-2">Behavior: {behaviorState.label}</span>
                  <span className="text-[10px] font-mono shrink-0 uppercase font-bold">{behaviorState.badge}</span>
                </div>
                <div className={`px-2.5 py-1.5 rounded-lg border text-xs flex items-center justify-between transition-colors ${timingState.tone}`}>
                  <span className="font-medium truncate mr-2">Timing: {timingState.label}</span>
                  <span className="text-[10px] font-mono shrink-0 uppercase font-bold">{timingState.badge}</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-ink-400 font-mono">
              <span>Telemetry Ingestion</span>
              <span className="text-brand-cyan font-semibold">Active &rarr;</span>
            </div>
          </div>

          {/* ======================================================== */}
          {/* STAGE 02 — RISK ANALYSIS */}
          {/* ======================================================== */}
          <div className="rounded-2xl border border-white/10 bg-space-850/60 p-5 flex flex-col justify-between hover:border-brand-luminous/40 transition-all relative overflow-hidden">
            {/* Soft Radar Sweep Behind Score */}
            <div className="pointer-events-none absolute -right-12 -top-12 w-48 h-48 rounded-full border border-brand-luminous/20 bg-gradient-to-tr from-brand-luminous/10 to-transparent animate-ag-spin-slow opacity-60" />

            <div>
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <span className="text-[11px] font-mono font-bold tracking-wider text-brand-cyan uppercase">02 — RISK ANALYSIS</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase" style={{ color: gaugeColor, backgroundColor: `${gaugeColor}20`, border: `1px solid ${gaugeColor}40` }}>
                  {result.riskTier} tier
                </span>
              </div>
              <h3 className="mt-3 text-base font-bold text-white tracking-tight">Evaluate changing signals</h3>
              <p className="text-xs text-ink-300 mt-1">Signals flow into deterministic additive scoring.</p>

              {/* Central Risk Hologram / Radial Scanner */}
              <div className="mt-5 flex flex-col items-center justify-center p-4 rounded-xl bg-space-900/80 border border-white/10 relative">
                <div className="flex items-baseline gap-1">
                  <span className="text-4xl font-extrabold tracking-tight transition-all duration-300" style={{ color: gaugeColor }}>
                    {result.score}
                  </span>
                  <span className="text-xs font-mono text-ink-400">/ 100</span>
                </div>
                <div className="mt-2 w-full">
                  <div className="h-2 rounded-full bg-space-800 overflow-hidden border border-white/5">
                    <div
                      className="h-full rounded-full transition-all duration-500 ease-out"
                      style={{ width: `${result.score}%`, backgroundColor: gaugeColor }}
                    />
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap justify-center gap-1.5 text-[10px] font-mono text-ink-400">
                  <span className="px-1.5 py-0.5 rounded bg-white/5">+{result.terms.base} base</span>
                  {result.terms.context > 0 && <span className="px-1.5 py-0.5 rounded bg-brand-blue/20 text-brand-cyan">+{result.terms.context} context</span>}
                  {result.terms.sequence > 0 && <span className="px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400">+{result.terms.sequence} sequence</span>}
                  {result.terms.timing > 0 && <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400">+{result.terms.timing} timing</span>}
                  {result.terms.baseline > 0 && <span className="px-1.5 py-0.5 rounded bg-brand-cyan/20 text-brand-cyan">+{result.terms.baseline} baseline</span>}
                  {result.terms.confidence > 0 && <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400">-{result.terms.confidence} confidence</span>}
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-ink-400 font-mono">
              <span>Risk Aggregation</span>
              <span style={{ color: gaugeColor }} className="font-semibold">{result.riskTier.toUpperCase()} &rarr;</span>
            </div>
          </div>

          {/* ======================================================== */}
          {/* STAGE 03 — POLICY DECISION */}
          {/* ======================================================== */}
          <div className="rounded-2xl border border-white/10 bg-space-850/60 p-5 flex flex-col justify-between hover:border-brand-luminous/40 transition-all">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <span className="text-[11px] font-mono font-bold tracking-wider text-brand-cyan uppercase">03 — POLICY DECISION</span>
                <span className="text-[10px] font-mono text-ink-400">PDP Engine</span>
              </div>
              <h3 className="mt-3 text-base font-bold text-white tracking-tight">Evaluate every action</h3>
              <p className="text-xs text-ink-300 mt-1">Requested action evaluated against security policies.</p>

              {/* Action & Policy Evaluation Card */}
              <div className="mt-4 p-3.5 rounded-xl bg-space-900/80 border border-white/10 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-ink-300">Target Action:</span>
                  <span className="text-xs font-semibold text-white px-2 py-0.5 rounded bg-white/5">{currentAction.label}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-ink-300">Action Sensitivity:</span>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase" style={{ color: gaugeColor, backgroundColor: `${gaugeColor}15` }}>
                    {result.sensitivity}
                  </span>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-white/5">
                  <span className="text-xs text-ink-300">Base Matrix Verdict:</span>
                  <span className="text-xs font-mono font-bold text-ink-200 capitalize">{result.baseDecision}</span>
                </div>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-ink-400">Escalation Rules:</span>
                  <span className={result.fired.length > 0 ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                    {result.fired.length > 0 ? `${result.fired.length} Fired (Escalated)` : '0 (Base Applies)'}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] text-ink-400 font-mono">
              <span>Decision Routing</span>
              <span className="text-brand-cyan font-semibold">Strict Verdict &rarr;</span>
            </div>
          </div>

          {/* ======================================================== */}
          {/* STAGE 04 — RESPONSE */}
          {/* ======================================================== */}
          <div className="rounded-2xl border border-white/10 bg-space-850/60 p-5 flex flex-col justify-between hover:border-brand-luminous/40 transition-all">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-white/10">
                <span className="text-[11px] font-mono font-bold tracking-wider text-brand-cyan uppercase">04 — RESPONSE</span>
                <span className="text-[10px] font-mono text-ink-400">5 Tiers</span>
              </div>
              <h3 className="mt-3 text-base font-bold text-white tracking-tight">Proportional friction</h3>
              <p className="text-xs text-ink-300 mt-1">Five graduated responses enforced before route runs.</p>

              {/* 5 Response Outcome Micro-Cards */}
              <div className="mt-4 space-y-1.5" data-testid="pipeline-response-cards">
                {DECISION_ORDER.map((id) => {
                  const meta = TIER_META[id];
                  const isActive = result.decision === id;
                  return (
                    <div
                      key={id}
                      className={`px-3 py-2 rounded-xl border flex items-center justify-between transition-all duration-300 ${
                        isActive
                          ? 'border-brand-cyan bg-white/10 shadow-[0_0_20px_rgba(53,197,232,0.3)] scale-[1.02]'
                          : 'border-white/5 bg-space-900/40 opacity-40 hover:opacity-75'
                      }`}
                      style={isActive ? { borderColor: meta.color, backgroundColor: `${meta.color}15` } : undefined}
                    >
                      <div className="flex items-center gap-2">
                        <span style={{ color: meta.color }}>{RESPONSE_ICONS[id]}</span>
                        <span className={`text-xs font-bold capitalize ${isActive ? 'text-white' : 'text-ink-300'}`}>
                          {meta.label}
                        </span>
                      </div>
                      {isActive && (
                        <span
                          className="px-2 py-0.5 rounded-full text-[9px] font-mono font-extrabold uppercase animate-pulse"
                          style={{ color: meta.color, backgroundColor: `${meta.color}25` }}
                        >
                          Active Verdict
                        </span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[11px] font-mono">
              <span className="text-ink-400">Enforcement</span>
              <span className="font-bold uppercase" style={{ color: tierMeta.color }}>
                {tierMeta.label}
              </span>
            </div>
          </div>

        </div>

        {/* ======================================================== */}
        {/* STAGE 05 — CONTINUOUS TRUST (Animated Loop Back) */}
        {/* ======================================================== */}
        <div className="relative rounded-2xl border border-brand-luminous/30 bg-gradient-to-r from-space-850/90 via-brand-navy/60 to-space-850/90 p-5 shadow-lg shadow-brand-luminous/10 overflow-hidden">
          {/* Animated Connecting Loop Circuit */}
          <div className="absolute inset-0 pointer-events-none opacity-30" aria-hidden="true">
            <div className="w-full h-full bg-gradient-to-r from-transparent via-brand-cyan/20 to-transparent animate-ag-shimmer" />
          </div>

          <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="h-10 w-10 rounded-xl bg-brand-cyan/15 border border-brand-cyan/40 flex items-center justify-center text-brand-cyan shrink-0 animate-ag-spin-slow">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono font-bold tracking-wider text-brand-cyan uppercase">05 — CONTINUOUS TRUST</span>
                  <span className="text-xs text-ink-400">&bull;</span>
                  <span className="text-xs font-medium text-ink-200">Session Security Loop</span>
                </div>
                <p className="text-sm font-semibold text-white mt-0.5">
                  Trust never stops being evaluated.
                </p>
                <p className="text-xs text-ink-300 mt-0.5">
                  Every subsequent action flows back into telemetry collection &mdash; authorization is continuous, dynamic, and never a one-time gate.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <span className="px-3 py-1.5 rounded-lg border border-brand-cyan/30 bg-brand-cyan/10 text-xs font-mono text-brand-cyan font-bold flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-brand-cyan animate-pulse" />
                Live Continuous Monitoring Loop &rarr;
              </span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}

export default VisualSecurityFlow;
