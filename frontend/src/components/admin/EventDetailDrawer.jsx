import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { TierBadge } from '../common/TierBadge.jsx';

/**
 * Slide-over detail drawer for inspecting real-time or historical events,
 * risk assessments, contributing signals, and policy decisions.
 *
 * Implements accessible modal behavior:
 * - Listens for 'Escape' key to close
 * - Restores focus to the triggering element upon closure
 * - Declares role="dialog", aria-modal="true", and aria-labelledby="drawer-title"
 *
 * @param {{
 *   event: any | null,
 *   onClose: () => void
 * }} props
 */
export function EventDetailDrawer({ event, onClose }) {
  const closeButtonRef = useRef(null);
  const previousActiveElement = useRef(null);

  useEffect(() => {
    if (event) {
      previousActiveElement.current = document.activeElement;
      // Focus close button on open
      setTimeout(() => {
        if (closeButtonRef.current) {
          closeButtonRef.current.focus();
        }
      }, 50);

      const handleKeyDown = (e) => {
        if (e.key === 'Escape') {
          e.preventDefault();
          onClose();
        }
      };

      window.addEventListener('keydown', handleKeyDown);
      return () => {
        window.removeEventListener('keydown', handleKeyDown);
        if (previousActiveElement.current && typeof previousActiveElement.current.focus === 'function') {
          previousActiveElement.current.focus();
        }
      };
    }
  }, [event, onClose]);

  if (!event) {
    return null;
  }

  // Normalize event structure from socket payload { eventType, data } or direct entity
  const data = event.data || event;
  const eventId = data.event_id || data.id || 'N/A';
  const eventType = data.event_type || data.action_type || event.eventType || 'N/A';
  const userId = data.user_id || 'N/A';
  const sessionId = data.session_id || 'N/A';
  const timestamp = data.timestamp || data.decided_at || data.evaluated_at || event.receivedAt || null;
  const riskTier = data.risk_tier || (data.assessment && data.assessment.risk_tier);
  const riskScore = data.risk_score !== undefined ? data.risk_score : (data.assessment && data.assessment.risk_score);
  const decision = data.effective_decision || data.decision || data.recommended_decision;
  const decisionId = data.decision_id || (data.decision && data.decision.decision_id);
  const signals = data.contributing_signals || (data.assessment && data.assessment.contributing_signals) || [];
  const reasons = data.reasons || [];
  const explanation = data.explanation || (data.assessment && data.assessment.explanation) || {};
  const coarseLocation = data.coarse_location;
  const deviceRef = data.device_ref;

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
      data-testid="event-detail-drawer"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50 transition-opacity"
        onClick={onClose}
        aria-hidden="true"
        data-testid="drawer-backdrop"
      />

      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-white shadow-xl flex flex-col">
          {/* Header */}
          <div className="px-6 py-4 bg-gray-50 border-b border-gray-200 flex items-center justify-between">
            <h2 id="drawer-title" className="text-lg font-bold text-gray-900" data-testid="drawer-title">
              Event Details
            </h2>
            <button
              ref={closeButtonRef}
              type="button"
              onClick={onClose}
              data-testid="drawer-close-button"
              aria-label="Close details"
              className="rounded-md text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 p-1"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6 text-sm text-gray-700">
            {/* Core Identifiers */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-900">Type</span>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-semibold bg-gray-100 text-gray-800">
                  {String(eventType)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-900">Event ID</span>
                <span className="font-mono text-xs text-gray-600 truncate max-w-[200px]" title={String(eventId)}>
                  {String(eventId)}
                </span>
              </div>
              {timestamp && (
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-gray-900">Timestamp</span>
                  <span className="text-xs text-gray-600">{new Date(timestamp).toLocaleString()}</span>
                </div>
              )}
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-900">User ID</span>
                <span className="font-mono text-xs text-indigo-600 truncate max-w-[200px]" title={String(userId)}>
                  {String(userId)}
                </span>
              </div>
              {sessionId !== 'N/A' && (
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-gray-900">Session ID</span>
                  <span className="font-mono text-xs text-gray-600 truncate max-w-[200px]" title={String(sessionId)}>
                    {String(sessionId)}
                  </span>
                </div>
              )}
              {deviceRef && (
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-gray-900">Device Ref</span>
                  <span className="font-mono text-xs text-gray-600">{String(deviceRef)}</span>
                </div>
              )}
              {coarseLocation && (
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-gray-900">Location</span>
                  <span className="text-xs text-gray-600">
                    {coarseLocation.country} {coarseLocation.region ? `(${coarseLocation.region})` : ''}
                  </span>
                </div>
              )}
            </div>

            <hr className="border-gray-200" />

            {/* Risk Assessment */}
            <div className="space-y-3">
              <h3 className="font-bold text-gray-900 text-base">Risk Assessment</h3>
              <div className="flex items-center justify-between">
                <span className="font-medium text-gray-700">Risk Tier</span>
                {riskTier ? <TierBadge tier={riskTier} /> : <span className="text-xs text-gray-400">N/A</span>}
              </div>
              {riskScore !== undefined && riskScore !== null && (
                <div className="flex items-center justify-between">
                  <span className="font-medium text-gray-700">Risk Score</span>
                  <span className="font-mono font-bold text-gray-900">{String(riskScore)}</span>
                </div>
              )}

              {/* Signals */}
              {signals && signals.length > 0 && (
                <div className="mt-3">
                  <span className="font-medium text-gray-700 block mb-1">Contributing Signals:</span>
                  <ul className="divide-y divide-gray-100 bg-gray-50 rounded border border-gray-200">
                    {signals.map((sig, idx) => (
                      <li key={idx} className="px-3 py-2 flex items-center justify-between text-xs">
                        <div>
                          <span className="font-mono font-medium text-gray-800">{String(sig.signal)}</span>
                          {sig.category && (
                            <span className="ml-1 text-[10px] text-gray-500 uppercase">({String(sig.category)})</span>
                          )}
                        </div>
                        <span
                          className={`font-mono font-semibold ${
                            Number(sig.weight) < 0 ? 'text-emerald-600' : 'text-red-600'
                          }`}
                        >
                          {Number(sig.weight) > 0 ? `+${sig.weight}` : sig.weight}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Policy Decision */}
            {(decision || reasons.length > 0) && (
              <>
                <hr className="border-gray-200" />
                <div className="space-y-3">
                  <h3 className="font-bold text-gray-900 text-base">Policy Enforcement</h3>
                  {decision && (
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-gray-700">Decision</span>
                      <span className="inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wide bg-indigo-50 text-indigo-700 border border-indigo-200">
                        {String(decision)}
                      </span>
                    </div>
                  )}

                  {reasons && reasons.length > 0 && (
                    <div className="mt-2">
                      <span className="font-medium text-gray-700 block mb-1">Evaluation Reasons:</span>
                      <ul className="space-y-1.5">
                        {reasons.map((r, idx) => (
                          <li key={idx} className="text-xs bg-gray-50 p-2 rounded border border-gray-200">
                            <span className="font-semibold text-gray-800">{r.rule_id || r.source}:</span>{' '}
                            <span>{r.reason || r.decision || 'Triggered'}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Explanations */}
            {(explanation.user_facing || explanation.admin_facing) && (
              <>
                <hr className="border-gray-200" />
                <div className="space-y-3">
                  <h3 className="font-bold text-gray-900 text-base">Explanations</h3>
                  {explanation.user_facing && (
                    <div className="bg-blue-50 border border-blue-200 rounded p-3 text-xs">
                      <span className="font-semibold text-blue-900 block mb-1">User Explanation:</span>
                      <p className="text-blue-800">{String(explanation.user_facing)}</p>
                    </div>
                  )}
                  {explanation.admin_facing && (
                    <div className="bg-slate-50 border border-slate-200 rounded p-3 text-xs">
                      <span className="font-semibold text-slate-900 block mb-1">Admin Audit Reason:</span>
                      <p className="text-slate-800 font-mono">{String(explanation.admin_facing)}</p>
                    </div>
                  )}
                </div>
              </>
            )}

            {/* Link to Decision Graph */}
            {decisionId && userId !== 'N/A' && (
              <div className="pt-2">
                <Link
                  to={`/admin/users/${userId}/decisions/${decisionId}`}
                  data-testid="drawer-view-graph-link"
                  className="w-full inline-flex items-center justify-center px-4 py-2 border border-transparent text-xs font-semibold rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  View Decision Explanation Graph &rarr;
                </Link>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
