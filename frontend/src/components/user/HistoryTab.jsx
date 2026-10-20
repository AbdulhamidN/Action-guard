import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../common/TierBadge.jsx';
import { Spinner } from '../common/Spinner.jsx';
import { EmptyState } from '../common/EmptyState.jsx';

/**
 * Renders an accessible outcome badge for user security decisions.
 */
function OutcomeBadge({ outcome }) {
  const normalized = typeof outcome === 'string' ? outcome.toLowerCase() : 'unknown';
  let badgeStyle = 'bg-gray-100 text-gray-800 border-gray-300';
  if (normalized === 'allow') {
    badgeStyle = 'bg-green-100 text-green-800 border-green-300';
  } else if (normalized === 'monitor') {
    badgeStyle = 'bg-blue-100 text-blue-800 border-blue-300';
  } else if (normalized === 'reverify') {
    badgeStyle = 'bg-amber-100 text-amber-800 border-amber-300';
  } else if (normalized === 'delay') {
    badgeStyle = 'bg-orange-100 text-orange-800 border-orange-300';
  } else if (normalized === 'block' || normalized === 'contained_and_blocked') {
    badgeStyle = 'bg-red-100 text-red-800 border-red-300';
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${badgeStyle}`}
      data-testid={`outcome-badge-${normalized}`}
    >
      {outcome || 'N/A'}
    </span>
  );
}

/**
 * HistoryTab displays the user's security events and policy decision history.
 * Strictly adheres to privacy protections:
 * - Shows user-facing explanations only.
 * - Shows risk tier only; never raw numeric risk scores.
 * - Never renders raw IP, user agent, or device fingerprint.
 */
export function HistoryTab() {
  const [decisions, setDecisions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [outcomeFilter, setOutcomeFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const fetchDecisions = useCallback(async (beforeTimestamp = null) => {
    const isInitial = !beforeTimestamp;
    if (isInitial) {
      setLoading(true);
      setError(null);
    } else {
      setLoadingMore(true);
    }

    try {
      const endpoint = beforeTimestamp
        ? `/me/decisions?limit=25&before=${encodeURIComponent(beforeTimestamp)}`
        : '/me/decisions?limit=25';

      const items = await apiRequest(endpoint, { authMode: 'user' });
      const records = Array.isArray(items) ? items : [];

      if (records.length < 25) {
        setHasMore(false);
      }

      setDecisions((prev) => (isInitial ? records : [...prev, ...records]));
    } catch (err) {
      setError(err.message || 'Failed to load security history');
    } finally {
      if (isInitial) {
        setLoading(false);
      } else {
        setLoadingMore(false);
      }
    }
  }, []);

  useEffect(() => {
    fetchDecisions();
  }, [fetchDecisions]);

  const handleLoadMore = () => {
    if (loadingMore || !hasMore || decisions.length === 0) return;
    const oldest = decisions[decisions.length - 1];
    if (oldest && oldest.decided_at) {
      fetchDecisions(oldest.decided_at);
    }
  };

  const filteredDecisions = useMemo(() => {
    return decisions.filter((d) => {
      if (typeFilter !== 'ALL' && d.action_type !== typeFilter) {
        return false;
      }
      if (outcomeFilter !== 'ALL' && d.decision !== outcomeFilter) {
        return false;
      }
      if (searchQuery.trim().length > 0) {
        const query = searchQuery.toLowerCase().trim();
        const actionMatch = d.action_type && d.action_type.toLowerCase().includes(query);
        const explanationMatch =
          d.explanation?.user_facing && d.explanation.user_facing.toLowerCase().includes(query);
        const idMatch = d.decision_id && d.decision_id.toLowerCase().includes(query);
        if (!actionMatch && !explanationMatch && !idMatch) {
          return false;
        }
      }
      return true;
    });
  }, [decisions, typeFilter, outcomeFilter, searchQuery]);

  const uniqueActionTypes = useMemo(() => {
    const types = new Set();
    decisions.forEach((d) => {
      if (d.action_type) types.add(d.action_type);
    });
    return Array.from(types).sort();
  }, [decisions]);

  const formatDate = (isoString) => {
    if (!isoString) return '—';
    try {
      return new Date(isoString).toLocaleString();
    } catch {
      return String(isoString);
    }
  };

  return (
    <div className="space-y-6" data-testid="history-tab">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h3 className="text-lg font-medium text-gray-900" data-testid="history-heading">
            Security History & Policy Decisions
          </h3>
          <p className="text-sm text-gray-500">
            Transparent audit log of protected actions and zero trust policy evaluations for your account.
          </p>
        </div>
        <button
          type="button"
          onClick={() => fetchDecisions()}
          disabled={loading}
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500 self-start sm:self-auto"
          data-testid="refresh-history-button"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div
          className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
          role="alert"
          data-testid="history-error"
        >
          {error}
        </div>
      )}

      {/* Filter Controls */}
      <div className="bg-white p-4 rounded-lg border border-gray-200 grid grid-cols-1 sm:grid-cols-3 gap-4" data-testid="history-filters">
        <div>
          <label htmlFor="history-search" className="block text-xs font-medium text-gray-700 mb-1">
            Search
          </label>
          <input
            id="history-search"
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search action or explanation..."
            className="w-full text-xs px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            data-testid="history-search-input"
          />
        </div>

        <div>
          <label htmlFor="history-type-filter" className="block text-xs font-medium text-gray-700 mb-1">
            Action Type
          </label>
          <select
            id="history-type-filter"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="w-full text-xs px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            data-testid="history-type-filter"
          >
            <option value="ALL">All Actions</option>
            {uniqueActionTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label htmlFor="history-outcome-filter" className="block text-xs font-medium text-gray-700 mb-1">
            Decision Outcome
          </label>
          <select
            id="history-outcome-filter"
            value={outcomeFilter}
            onChange={(e) => setOutcomeFilter(e.target.value)}
            className="w-full text-xs px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
            data-testid="history-outcome-filter"
          >
            <option value="ALL">All Outcomes</option>
            <option value="allow">Allow</option>
            <option value="monitor">Monitor</option>
            <option value="reverify">Reverify</option>
            <option value="delay">Delay</option>
            <option value="block">Block</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-12" data-testid="history-loading">
          <Spinner />
        </div>
      ) : filteredDecisions.length === 0 ? (
        <EmptyState
          title="No security records found"
          description={
            decisions.length === 0
              ? 'No security events or policy decisions have been recorded for your account yet.'
              : 'No decisions match your current filter criteria.'
          }
        />
      ) : (
        <div className="bg-white shadow overflow-hidden sm:rounded-md border border-gray-200">
          <ul className="divide-y divide-gray-200" data-testid="history-list">
            {filteredDecisions.map((d) => (
              <li
                key={d.decision_id || d.event_id}
                className="p-4 sm:px-6 hover:bg-gray-50 space-y-2"
                data-testid={`history-item-${d.decision_id}`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                  <div className="flex items-center space-x-3">
                    <span className="font-medium text-sm text-gray-900" data-testid="history-action-type">
                      {d.action_type || 'Unknown Action'}
                    </span>
                    <OutcomeBadge outcome={d.decision} />
                    <TierBadge tier={d.risk_tier || 'low'} />
                  </div>
                  <span className="text-xs text-gray-500 font-mono" data-testid="history-timestamp">
                    {formatDate(d.decided_at)}
                  </span>
                </div>

                {d.explanation?.user_facing && (
                  <p className="text-sm text-gray-600 bg-gray-50 p-2.5 rounded border border-gray-100" data-testid="history-explanation">
                    {d.explanation.user_facing}
                  </p>
                )}

                <div className="flex items-center space-x-4 text-xs text-gray-400 font-mono">
                  <span>ID: {d.decision_id}</span>
                  {d.session_id && <span>Session: {d.session_id}</span>}
                  {d.enforcement_outcome && <span>Enforcement: {d.enforcement_outcome}</span>}
                </div>
              </li>
            ))}
          </ul>

          {hasMore && (
            <div className="p-4 bg-gray-50 border-t border-gray-200 text-center">
              <button
                type="button"
                onClick={handleLoadMore}
                disabled={loadingMore}
                className="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                data-testid="history-load-more-button"
              >
                {loadingMore && <Spinner className="w-4 h-4 mr-2" />}
                {loadingMore ? 'Loading older records...' : 'Load older records'}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
