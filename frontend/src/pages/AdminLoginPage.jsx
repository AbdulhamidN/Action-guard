import React, { useState, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { setAdminToken } from '../services/authStorage.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';
import { AmbientBackground } from '../components/common/AmbientBackground.jsx';

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
    <div className="min-h-screen relative flex items-center justify-center bg-space-950 py-12 px-4 sm:px-6 lg:px-8 overflow-hidden text-ink-100">
      <AmbientBackground variant="admin" />

      <div className="relative max-w-md w-full space-y-8 bg-space-850/90 backdrop-blur-xl p-8 sm:p-10 rounded-2xl shadow-2xl border border-white/10 ring-1 ring-white/5">
        <div>
          <div className="mx-auto h-12 w-12 bg-gradient-to-br from-red-500 via-rose-600 to-red-700 rounded-xl flex items-center justify-center text-white font-black text-xl shadow-lg shadow-red-500/30">
            AG
          </div>
          <h2 className="mt-6 text-center text-2xl font-extrabold text-white tracking-tight" data-testid="page-title">
            Admin Login
          </h2>
          <p className="mt-2 text-center text-xs font-mono text-ink-400">
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
            <label htmlFor="admin-key" className="block text-xs font-semibold uppercase tracking-wider text-ink-300 mb-2 font-mono">
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
              className="appearance-none rounded-xl relative block w-full px-4 py-2.5 border border-white/15 bg-space-900 placeholder-ink-500 text-white focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-red-500 text-sm font-mono transition-all disabled:opacity-60"
              placeholder="••••••••••••••••••••••••••••••••"
            />
            <p className="mt-2 text-xs text-ink-500 leading-relaxed">
              Key is transmitted once to establish an in-memory session and cleared immediately.
            </p>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              data-testid="admin-submit-button"
              className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-xl text-white bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-all shadow-lg shadow-red-600/30 disabled:opacity-50 hover:scale-[1.01]"
            >
              {loading ? <Spinner size="sm" label="Verifying Key..." /> : 'Authenticate Operator'}
            </button>
          </div>
        </form>

        <div className="pt-4 border-t border-white/5 flex items-center justify-between text-xs text-ink-400">
          <Link to="/" className="hover:text-brand-cyan transition-colors">
            &larr; Back to Public Site
          </Link>
          <Link to="/login" className="hover:text-brand-cyan transition-colors">
            User Login &rarr;
          </Link>
        </div>
      </div>
    </div>
  );
}

export default AdminLoginPage;
