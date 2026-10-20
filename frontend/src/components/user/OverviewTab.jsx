import React, { useEffect, useState } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../common/TierBadge.jsx';
import { Spinner } from '../common/Spinner.jsx';
import { ErrorBanner } from '../common/ErrorBanner.jsx';

const TIER_ADVICE = {
  low: 'Your current session looks normal. No action is needed.',
  medium: 'Some activity in this session is unusual. Extra verification may be requested.',
  high: 'This session shows elevated risk. Sensitive actions may be delayed or require verification.',
  critical: 'This session shows critical risk. Sensitive actions may be blocked.'
};

/**
 * Overview tab: summarizes the current session's risk tier and session counts.
 * Reads GET /api/v1/me/sessions only; shows tier and coarse location, never raw signals.
 */
export function OverviewTab() {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    apiRequest('/me/sessions', { authMode: 'user' })
      .then((data) => {
        if (!cancelled) setSessions(Array.isArray(data) ? data : []);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load session overview.');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) return <ErrorBanner message={error} onDismiss={() => setError(null)} />;
  if (!sessions) return <Spinner label="Loading overview..." />;

  const active = sessions.filter((s) => s.is_active);
  const current = sessions.find((s) => s.is_current) || null;
  const elevated = active.filter((s) => ['high', 'critical'].includes(s.risk?.risk_tier)).length;
  const currentTier = current?.risk?.risk_tier || 'unknown';

  return (
    <div className="space-y-4" data-testid="overview-tab">
      <div className="bg-white border border-gray-200 rounded-lg p-5 shadow-sm">
        <h3 className="text-sm font-semibold text-gray-900">Current session risk</h3>
        <div className="mt-3 flex items-center gap-3">
          <TierBadge tier={currentTier} />
          <span className="text-sm text-gray-600" data-testid="overview-advice">
            {TIER_ADVICE[currentTier] || 'Risk for this session has not been evaluated yet.'}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="bg-white border border-gray-200 rounded-lg p-5 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500">Active sessions</p>
          <p className="mt-1 text-2xl font-bold text-gray-900" data-testid="overview-active-count">
            {active.length}
          </p>
        </div>
        <div className="bg-white border border-gray-200 rounded-lg p-5 shadow-sm">
          <p className="text-xs uppercase tracking-wider text-gray-500">High or critical risk</p>
          <p className="mt-1 text-2xl font-bold text-gray-900" data-testid="overview-elevated-count">
            {elevated}
          </p>
        </div>
      </div>
    </div>
  );
}

export default OverviewTab;
