import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { setUserToken } from '../services/authStorage.js';
import { getDeviceFingerprint } from '../services/fingerprint.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';
import { DECISION_ORDER, TIER_META } from '../components/landing/tiers.js';

/**
 * User login page.
 * Authenticates against POST /api/v1/auth/login with the x-device-fingerprint header.
 * Stores JWT strictly in sessionStorage.
 */
export function UserLoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const justRegistered = Boolean(location.state?.registered);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(/** @type {{ message: string, code?: string } | null} */ (null));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const fingerprint = await getDeviceFingerprint();

      const response = await apiRequest('/auth/login', {
        method: 'POST',
        authMode: 'none',
        headers: {
          'x-device-fingerprint': fingerprint
        },
        body: {
          email: email.trim(),
          password
        }
      });

      if (response && response.token) {
        setUserToken(response.token);
        navigate('/app');
      } else {
        throw new Error('Authentication response did not contain a valid session token.');
      }
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, code: err.code });
      } else {
        setError({ message: err.message || 'An unexpected error occurred during login.' });
      }
    } finally {
      setLoading(false);
    }
  };

  const inputClass =
    'block w-full rounded-lg bg-space-800 border border-white/10 px-3 py-2.5 text-sm text-ink-100 placeholder-ink-500 focus:outline-none focus:border-neon-cyan focus:ring-1 focus:ring-neon-cyan disabled:opacity-60';
  const labelClass = 'block text-xs font-semibold uppercase tracking-wider text-ink-300 mb-1';

  return (
    <div className="min-h-screen bg-space-900 text-ink-100 relative overflow-hidden flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <div className="pointer-events-none absolute -top-24 left-1/3 h-80 w-80 rounded-full bg-neon-indigo/20 blur-[120px] animate-ag-glow" aria-hidden="true" />
      <svg className="pointer-events-none absolute right-[-60px] bottom-[-60px] h-96 w-96 opacity-[0.07]" viewBox="0 0 200 200" aria-hidden="true" focusable="false">
        <path d="M100 10 L160 34 V96 C160 136 132 160 100 176 C68 160 40 136 40 96 V34 Z" fill="none" stroke="#06B6D4" strokeWidth="6" />
      </svg>

      <div className="relative w-full max-w-4xl grid md:grid-cols-2 rounded-2xl overflow-hidden border border-white/10 bg-white/[0.04] backdrop-blur-md shadow-[0_0_60px_-15px_rgba(99,102,241,0.35)]">
        <aside className="hidden md:flex flex-col justify-between p-8 bg-space-800/60 border-r border-white/10">
          <div>
            <div className="h-10 w-10 rounded-xl bg-neon-indigo flex items-center justify-center font-bold" aria-hidden="true">AG</div>
            <h2 className="mt-6 text-2xl font-extrabold tracking-tight">Never trust a session. Verify every action.</h2>
            <p className="mt-3 text-sm text-ink-300">
              ActionGuard re-evaluates sensitive actions against current context and responds in proportion to the risk.
            </p>
          </div>
          <ol className="mt-8 space-y-2" aria-label="Response tiers from least to most friction">
            {DECISION_ORDER.map((id, i) => (
              <li key={id} className="flex items-center gap-3 text-sm">
                <span className="h-2.5 rounded-full" style={{ width: `${(i + 1) * 20}%`, background: TIER_META[id].color }} aria-hidden="true" />
                <span style={{ color: TIER_META[id].color }}>{id}</span>
              </li>
            ))}
          </ol>
        </aside>

        <div className="p-8 space-y-6">
          <div>
            <h2 className="text-2xl font-extrabold tracking-tight" data-testid="page-title">
              User Login
            </h2>
            <p className="mt-1 text-sm text-ink-300">
              ActionGuard Zero Trust User Session Authentication
            </p>
          </div>

          {justRegistered && !error && (
            <div className="rounded-lg bg-state-ok/10 border border-state-ok/40 p-3 text-sm text-state-ok" data-testid="registered-notice">
              Account created. Please sign in.
            </div>
          )}

          {error && (
            <ErrorBanner
              message={error.message}
              code={error.code}
              onDismiss={() => setError(null)}
            />
          )}

          <form className="space-y-5" onSubmit={handleSubmit}>
            <div className="space-y-4">
              <div>
                <label htmlFor="user-email" className={labelClass}>
                  Email Address
                </label>
                <input
                  id="user-email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={loading}
                  className={inputClass}
                  placeholder="user@example.com"
                />
              </div>

              <div>
                <label htmlFor="user-password" className={labelClass}>
                  Password
                </label>
                <input
                  id="user-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={loading}
                  className={inputClass}
                  placeholder="••••••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full flex justify-center py-2.5 px-4 text-sm font-semibold rounded-lg text-white bg-gradient-to-r from-neon-indigo to-neon-cyan hover:brightness-110 transition disabled:opacity-50"
            >
              {loading ? <Spinner size="sm" label="Authenticating..." /> : 'Sign In'}
            </button>
          </form>

          <p className="text-xs text-ink-500">
            We verify your device and session, not just your password.
          </p>

          <p className="text-sm text-ink-300">
            Access is provisioned by your organization.{' '}
            <Link to="/signup" className="font-medium text-neon-cyan hover:underline underline-offset-4" data-testid="signup-link">
              Need an account?
            </Link>
          </p>
          <p className="text-sm">
            <Link to="/" className="text-ink-500 hover:text-ink-300">&larr; Back to overview</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
