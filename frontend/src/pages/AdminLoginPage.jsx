import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { setAdminToken } from '../services/authStorage.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';

/**
 * Admin operator login page.
 * The admin API key is typed, sent once, and immediately discarded.
 * It is never persisted, never logged, and the input field is cleared upon submission.
 * Admin tokens are held strictly in memory.
 */
export function AdminLoginPage() {
  const navigate = useNavigate();
  const [adminKey, setAdminKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(/** @type {{ message: string, code?: string } | null} */ (null));
  const inputRef = useRef(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    // Capture key and immediately clear field and component state
    const submittedKey = adminKey;
    setAdminKey('');
    if (inputRef.current) {
      inputRef.current.value = '';
    }

    if (!submittedKey || submittedKey.length === 0) {
      setError({ message: 'Administrative API key is required.' });
      return;
    }

    setLoading(true);

    try {
      const response = await apiRequest('/admin/auth/login', {
        method: 'POST',
        authMode: 'none',
        body: {
          admin_key: submittedKey
        }
      });

      if (response && response.admin_token) {
        setAdminToken(response.admin_token);
        navigate('/admin');
      } else {
        throw new Error('Administrative authentication failed to issue an operator session token.');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, code: err.code });
      } else {
        setError({ message: err.message || 'Administrative authentication failed.' });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-slate-800 p-8 rounded-xl shadow-xl border border-slate-700">
        <div>
          <div className="mx-auto h-12 w-12 bg-red-600 rounded-xl flex items-center justify-center text-white font-bold text-xl shadow-lg">
            AG
          </div>
          <h2 className="mt-6 text-center text-2xl font-extrabold text-white" data-testid="page-title">
            Admin Login
          </h2>
          <p className="mt-2 text-center text-xs text-slate-400">
            Operator Console — Single-Use Key Authentication
          </p>
        </div>

        {error && (
          <ErrorBanner
            message={error.message}
            code={error.code}
            onDismiss={() => setError(null)}
          />
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div>
            <label htmlFor="admin-key" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
              Admin API Key
            </label>
            <input
              id="admin-key"
              ref={inputRef}
              name="adminKey"
              type="password"
              autoComplete="off"
              required
              value={adminKey}
              onChange={(e) => setAdminKey(e.target.value)}
              disabled={loading}
              data-testid="admin-key-input"
              className="appearance-none rounded-lg relative block w-full px-3 py-2 border border-slate-600 bg-slate-700 placeholder-slate-400 text-white focus:outline-none focus:ring-red-500 focus:border-red-500 text-sm font-mono"
              placeholder="••••••••••••••••••••••••••••••••"
            />
            <p className="mt-1 text-xs text-slate-400">
              Key is transmitted once to establish an in-memory session and cleared immediately.
            </p>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              data-testid="admin-submit-button"
              className="group relative w-full flex justify-center py-2.5 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors shadow-sm disabled:opacity-50"
            >
              {loading ? <Spinner size="sm" label="Verifying Key..." /> : 'Authenticate Operator'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
