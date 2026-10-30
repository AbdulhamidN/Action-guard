import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { setUserToken } from '../services/authStorage.js';
import { getDeviceFingerprint } from '../services/fingerprint.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';
import { AmbientBackground } from '../components/common/AmbientBackground.jsx';
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
    'block w-full rounded-xl bg-space-900 border border-white/15 px-4 py-2.5 text-sm text-white placeholder-ink-500 focus:outline-none focus:border-brand-cyan focus:ring-1 focus:ring-brand-cyan disabled:opacity-60 transition-all font-mono';
  const labelClass = 'block text-xs font-semibold uppercase tracking-wider text-ink-300 mb-1.5 font-mono';

  return (
    <div className="min-h-screen bg-space-950 text-ink-100 relative overflow-hidden flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      <AmbientBackground variant="subtle" />

      <div className="relative w-full max-w-4xl grid md:grid-cols-2 rounded-2xl overflow-hidden border border-white/10 bg-space-850/90 backdrop-blur-xl shadow-2xl ring-1 ring-white/5">
        <aside className="hidden md:flex flex-col justify-between p-8 bg-space-900/70 border-r border-white/10">
          <div>
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-brand-luminous to-brand-blue flex items-center justify-center font-bold text-white shadow-md shadow-brand-luminous/30" aria-hidden="true">AG</div>
            <h2 className="mt-6 text-2xl font-extrabold tracking-tight text-white">Never trust a session. Verify every action.</h2>
            <p className="mt-3 text-sm text-ink-300 leading-relaxed">
              ActionGuard re-evaluates sensitive actions against current context and responds in proportion to evaluated risk.
            </p>
          </div>
          <ol className="mt-8 space-y-2.5" aria-label="Response tiers from least to most friction">
            {DECISION_ORDER.map((id, i) => (
              <li key={id} className="flex items-center gap-3 text-xs font-mono font-bold">
                <span className="h-2 rounded-full" style={{ width: `${(i + 1) * 20}%`, background: TIER_META[id].color }} aria-hidden="true" />
                <span style={{ color: TIER_META[id].color }}>{id}</span>
              </li>
            ))}
          </ol>
        </aside>

        <div className="p-8 sm:p-10 space-y-6">
          <div>
            <h2 className="text-2xl font-extrabold tracking-tight text-white" data-testid="page-title">
              User Login
            </h2>
            <p className="mt-1 text-sm text-ink-400">
              ActionGuard Zero Trust User Session Authentication
            </p>
          </div>

          {justRegistered && !error && (
            <div className="rounded-xl bg-emerald-500/10 border border-emerald-500/40 p-3 text-sm text-emerald-400" data-testid="registered-notice">
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
              className="w-full flex justify-center py-3 px-4 text-sm font-bold rounded-xl text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan hover:brightness-110 transition-all shadow-lg shadow-brand-luminous/30 disabled:opacity-50 hover:scale-[1.01]"
            >
              {loading ? <Spinner size="sm" label="Authenticating..." /> : 'Sign In'}
            </button>
          </form>

          <p className="text-xs text-ink-500">
            We verify your device and session context, not just your password.
          </p>

          <div className="pt-2 border-t border-white/5 space-y-2 text-sm">
            <p className="text-ink-300">
              Access is provisioned by your organization.{' '}
              <Link to="/signup" className="font-semibold text-brand-cyan hover:underline underline-offset-4" data-testid="signup-link">
                Need an account?
              </Link>
            </p>
            <p>
              <Link to="/" className="text-ink-400 hover:text-white transition-colors">&larr; Back to overview</Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default UserLoginPage;
