import React, { useState, useEffect, useCallback, useRef } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { getCancellationToken, removeCancellationToken } from '../../services/cancellationStorage.js';
import { Spinner } from '../common/Spinner.jsx';
import { EmptyState } from '../common/EmptyState.jsx';
import { TierBadge } from '../common/TierBadge.jsx';

/**
 * Status badge for delayed actions.
 */
function ActionStatusBadge({ status }) {
  const normalized = typeof status === 'string' ? status.toLowerCase() : 'unknown';
  let style = 'bg-gray-100 text-gray-800 border-gray-300';
  if (normalized === 'pending') {
    style = 'bg-amber-100 text-amber-800 border-amber-300';
  } else if (normalized === 'executed') {
    style = 'bg-green-100 text-green-800 border-green-300';
  } else if (normalized === 'cancelled') {
    style = 'bg-gray-100 text-gray-600 border-gray-300';
  } else if (normalized === 'rejected' || normalized === 'failed') {
    style = 'bg-red-100 text-red-800 border-red-300';
  }

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${style}`}
      data-testid={`delayed-status-${normalized}`}
    >
      {status || 'Unknown'}
    </span>
  );
}

/**
 * CoolingOffTab displays and manages pending delayed actions under cooling-off protection.
 * Adheres to Zero Trust delayed action requirements:
 * - Uses cancellation tokens stored strictly in sessionStorage.
 * - Updates countdowns live with proper cleanup on unmount.
 * - Enables execution only once cooling-off window has elapsed.
 * - Provides immediate feedback upon cancellation.
 */
export function CoolingOffTab() {
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [cancellingId, setCancellingId] = useState(null);
  const [executingId, setExecutingId] = useState(null);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [nowMs, setNowMs] = useState(Date.now());

  // Input state for manual cancellation token entry if not present in sessionStorage
  const [manualTokens, setManualTokens] = useState({});

  const timerRef = useRef(null);

  const fetchActions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiRequest('/cooling-off/actions', { authMode: 'user' });
      const items = data && Array.isArray(data.actions) ? data.actions : [];
      setActions(items);
    } catch (err) {
      setError(err.message || 'Failed to load delayed actions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchActions();
  }, [fetchActions]);

  // Live countdown ticker updated every second with clean teardown
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setNowMs(Date.now());
    }, 1000);

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, []);

  const handleCancelAction = async (actionId) => {
    if (!actionId || cancellingId) return;

    // Retrieve token from sessionStorage or manual fallback input
    const storedToken = getCancellationToken(actionId);
    const manualToken = manualTokens[actionId];
    const token = storedToken || (manualToken ? manualToken.trim() : '');

    setCancellingId(actionId);
    setError(null);
    setSuccessMessage(null);
    try {
      await apiRequest(`/cooling-off/actions/${actionId}/cancel`, {
        method: 'POST',
        body: {
          cancellation_token: token,
          reason: 'user_requested_cancellation_ui'
        },
        authMode: 'user'
      });

      // Clear token from sessionStorage upon successful cancellation
      removeCancellationToken(actionId);

      setSuccessMessage('Delayed action has been cancelled successfully.');
      await fetchActions();
    } catch (err) {
      setError(err.message || 'Failed to cancel delayed action');
    } finally {
      setCancellingId(null);
    }
  };

  const handleExecuteAction = async (actionId) => {
    if (!actionId || executingId) return;

    setExecutingId(actionId);
    setError(null);
    setSuccessMessage(null);
    try {
      await apiRequest(`/cooling-off/actions/${actionId}/execute`, {
        method: 'POST',
        authMode: 'user'
      });

      removeCancellationToken(actionId);
      setSuccessMessage('Delayed action executed successfully.');
      await fetchActions();
    } catch (err) {
      setError(err.message || 'Failed to execute delayed action');
    } finally {
      setExecutingId(null);
    }
  };

  const getRemainingSeconds = (executeAt) => {
    if (!executeAt) return 0;
    const targetMs = new Date(executeAt).getTime();
    const diffSec = Math.ceil((targetMs - nowMs) / 1000);
    return Math.max(0, diffSec);
  };

  const formatDate = (isoString) => {
    if (!isoString) return '—';
    try {
      return new Date(isoString).toLocaleString();
    } catch {
      return String(isoString);
    }
  };

  return (
    <div className="space-y-6" data-testid="cooling-off-tab">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium text-gray-900" data-testid="cooling-off-heading">
            Delayed Actions & Cooling-Off Period
          </h3>
          <p className="text-sm text-gray-500">
            Sensitive actions scheduled for delayed execution allowing you time to review or cancel suspicious requests.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchActions}
          disabled={loading}
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          data-testid="refresh-delayed-button"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div
          className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
          role="alert"
          data-testid="cooling-off-error"
        >
          {error}
        </div>
      )}

      {successMessage && (
        <div
          className="p-3 bg-green-50 border border-green-200 rounded text-sm text-green-700"
          role="alert"
          data-testid="cooling-off-success"
        >
          {successMessage}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12" data-testid="delayed-actions-loading">
          <Spinner />
        </div>
      ) : actions.length === 0 ? (
        <EmptyState
          title="No pending delayed actions"
          description="You do not have any actions currently undergoing a security cooling-off delay."
        />
      ) : (
        <div className="bg-white shadow overflow-hidden sm:rounded-md border border-gray-200">
          <ul className="divide-y divide-gray-200" data-testid="delayed-actions-list">
            {actions.map((act) => {
              const remainingSec = getRemainingSeconds(act.execute_at);
              const isPending = act.status === 'pending';
              const isEligibleToExecute = isPending && remainingSec <= 0;
              const hasStoredToken = Boolean(getCancellationToken(act.id));
              const isCancelling = cancellingId === act.id;
              const isExecuting = executingId === act.id;

              return (
                <li
                  key={act.id}
                  className="p-4 sm:px-6 hover:bg-gray-50 space-y-3"
                  data-testid={`delayed-action-item-${act.id}`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-sm font-semibold text-gray-900" data-testid="delayed-action-id">
                        {act.id}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-gray-100 text-gray-700 border">
                        {act.action_type}
                      </span>
                      <ActionStatusBadge status={act.status} />
                      <TierBadge tier={act.scheduled_at_risk_tier || 'low'} />
                    </div>

                    <div className="flex items-center space-x-2 text-xs font-mono">
                      {isPending ? (
                        <span
                          className={`font-semibold px-2 py-1 rounded ${
                            remainingSec > 0
                              ? 'bg-amber-50 text-amber-800 border border-amber-200'
                              : 'bg-green-50 text-green-800 border border-green-200'
                          }`}
                          data-testid="delayed-countdown"
                        >
                          {remainingSec > 0
                            ? `Cooling off: ${remainingSec}s remaining`
                            : 'Cooling-off complete — ready to execute'}
                        </span>
                      ) : (
                        <span className="text-gray-400">
                          {act.status}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-500">
                    <span>Scheduled: {formatDate(act.scheduled_at)}</span>
                    <span>Execute At: {formatDate(act.execute_at)}</span>
                    <span>Window: {act.cooling_off_seconds}s</span>
                  </div>

                  {isPending && (
                    <div className="pt-2 border-t border-gray-100 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      {!hasStoredToken && (
                        <div className="flex items-center space-x-2">
                          <label htmlFor={`manual-token-${act.id}`} className="text-xs text-gray-600">
                            Cancellation Token:
                          </label>
                          <input
                            id={`manual-token-${act.id}`}
                            type="text"
                            placeholder="Enter cancellation token"
                            value={manualTokens[act.id] || ''}
                            onChange={(e) =>
                              setManualTokens({
                                ...manualTokens,
                                [act.id]: e.target.value
                              })
                            }
                            className="text-xs px-2 py-1 border border-gray-300 rounded font-mono w-48 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                            data-testid={`manual-token-input-${act.id}`}
                          />
                        </div>
                      )}

                      <div className="flex items-center space-x-3 ml-auto">
                        <button
                          type="button"
                          onClick={() => handleCancelAction(act.id)}
                          disabled={isCancelling}
                          className="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50"
                          data-testid={`cancel-delayed-button-${act.id}`}
                        >
                          {isCancelling && <Spinner className="w-3.5 h-3.5 mr-1" />}
                          Cancel Action
                        </button>

                        <button
                          type="button"
                          onClick={() => handleExecuteAction(act.id)}
                          disabled={!isEligibleToExecute || isExecuting}
                          className="inline-flex items-center px-3 py-1.5 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 disabled:bg-gray-300"
                          data-testid={`execute-delayed-button-${act.id}`}
                        >
                          {isExecuting && <Spinner className="w-3.5 h-3.5 mr-1" />}
                          Execute Now
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
