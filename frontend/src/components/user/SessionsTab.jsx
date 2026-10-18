import React, { useState, useEffect, useCallback } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../common/TierBadge.jsx';
import { Spinner } from '../common/Spinner.jsx';
import { EmptyState } from '../common/EmptyState.jsx';

/**
 * SessionsTab displays active user sessions and allows terminating non-current sessions.
 * Strictly adheres to privacy protections:
 * - Displays coarse location (country, region) only.
 * - Displays risk tier badge only; never raw numeric risk scores.
 * - Never renders raw IP, user agent, or device fingerprint.
 *
 * @param {object} props
 * @param {string|null} [props.currentSessionId=null]
 * @param {() => void} [props.onSessionTerminated]
 */
export function SessionsTab({ currentSessionId = null, onSessionTerminated = null }) {
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [terminatingId, setTerminatingId] = useState(null);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  const fetchSessions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiRequest('/me/sessions', { authMode: 'user' });
      setSessions(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || 'Failed to load active sessions');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSessions();
  }, [fetchSessions]);

  const handleTerminateSession = async (sessionId) => {
    if (!sessionId || terminatingId) return;
    setTerminatingId(sessionId);
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await apiRequest(`/me/sessions/${sessionId}`, {
        method: 'DELETE',
        authMode: 'user'
      });
      setSuccessMessage(res.message || 'Session successfully terminated');
      // Refresh list
      await fetchSessions();
      if (typeof onSessionTerminated === 'function') {
        onSessionTerminated(sessionId);
      }
    } catch (err) {
      setError(err.message || 'Failed to terminate session');
    } finally {
      setTerminatingId(null);
    }
  };

  const formatLocation = (loc) => {
    if (!loc) return 'Unknown Location';
    if (typeof loc === 'string') return loc;
    const parts = [loc.region, loc.country].filter(Boolean);
    return parts.length > 0 ? parts.join(', ') : 'Unknown Location';
  };

  const formatDate = (isoString) => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return d.toLocaleString();
    } catch {
      return String(isoString);
    }
  };

  return (
    <div className="space-y-6" data-testid="sessions-tab">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-medium text-gray-900" data-testid="sessions-heading">
            Active Sessions
          </h3>
          <p className="text-sm text-gray-500">
            Manage your authenticated browser and client sessions across devices.
          </p>
        </div>
        <button
          type="button"
          onClick={fetchSessions}
          disabled={loading}
          className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          data-testid="refresh-sessions-button"
        >
          {loading ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div
          className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
          role="alert"
          data-testid="sessions-error"
        >
          {error}
        </div>
      )}

      {successMessage && (
        <div
          className="p-3 bg-green-50 border border-green-200 rounded text-sm text-green-700"
          role="alert"
          data-testid="sessions-success"
        >
          {successMessage}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center py-12" data-testid="sessions-loading">
          <Spinner />
        </div>
      ) : sessions.length === 0 ? (
        <EmptyState
          title="No active sessions found"
          description="You do not have any other recorded active sessions."
        />
      ) : (
        <div className="bg-white shadow overflow-hidden sm:rounded-md border border-gray-200">
          <ul className="divide-y divide-gray-200" data-testid="sessions-list">
            {sessions.map((sess) => {
              const isCurrent = sess.is_current || sess.session_id === currentSessionId;
              const isTerminating = terminatingId === sess.session_id;

              return (
                <li
                  key={sess.session_id}
                  className="p-4 sm:px-6 hover:bg-gray-50 flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0"
                  data-testid={`session-item-${sess.session_id}`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-mono text-sm font-semibold text-gray-900" data-testid="session-id">
                        {sess.session_id}
                      </span>
                      {isCurrent && (
                        <span
                          className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800"
                          data-testid="current-session-badge"
                        >
                          Current Session
                        </span>
                      )}
                      <TierBadge tier={sess.risk?.risk_tier || 'low'} />
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
                      <span data-testid="session-location">
                        📍 {formatLocation(sess.coarse_location)}
                      </span>
                      <span data-testid="session-created">
                        Started: {formatDate(sess.created_at)}
                      </span>
                      <span data-testid="session-expires">
                        Expires: {formatDate(sess.expires_at)}
                      </span>
                    </div>
                  </div>

                  <div>
                    {isCurrent ? (
                      <span className="text-xs text-gray-400 italic" data-testid="current-session-note">
                        Active (Use Sign Out)
                      </span>
                    ) : !sess.is_active ? (
                      <span className="text-xs text-gray-400 italic" data-testid={`session-terminated-${sess.session_id}`}>
                        Terminated
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleTerminateSession(sess.session_id)}
                        disabled={isTerminating}
                        className="inline-flex items-center px-3 py-1.5 border border-red-300 shadow-sm text-xs font-medium rounded text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-red-500 disabled:opacity-50"
                        data-testid={`terminate-session-${sess.session_id}`}
                      >
                        {isTerminating && <Spinner className="w-3.5 h-3.5 mr-1" />}
                        Terminate
                      </button>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
