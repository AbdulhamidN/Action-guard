import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';
import { AmbientBackground } from '../components/common/AmbientBackground.jsx';

const MIN_PASSWORD_LENGTH = 6;

/**
 * User signup page.
 * Registers against POST /api/v1/auth/signup, then sends the user to /login.
 */
export function UserSignupPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(/** @type {{ message: string, code?: string } | null} */ (null));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError({ message: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.` });
      return;
    }
    if (password !== confirmPassword) {
      setError({ message: 'Passwords do not match.' });
      return;
    }

    setLoading(true);
    try {
      await apiRequest('/auth/signup', {
        method: 'POST',
        authMode: 'none',
        body: { email: email.trim(), password }
      });
      navigate('/login', { state: { registered: true } });
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ message: err.message, code: err.code });
      } else {
        setError({ message: err.message || 'An unexpected error occurred during signup.' });
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

      <div className="max-w-md w-full space-y-8 bg-space-850/90 backdrop-blur-xl p-8 sm:p-10 rounded-2xl shadow-2xl border border-white/10 ring-1 ring-white/5 relative z-10">
        <div>
          <Link to="/" className="inline-block focus:outline-none">
            <div className="mx-auto h-12 w-12 rounded-xl bg-gradient-to-br from-brand-luminous to-brand-cyan flex items-center justify-center text-white font-extrabold text-xl shadow-lg shadow-brand-luminous/30">
              AG
            </div>
          </Link>
          <h2 className="mt-5 text-center text-2xl font-extrabold tracking-tight text-white" data-testid="page-title">
            Create Account
          </h2>
          <p className="mt-2 text-center text-xs font-mono text-ink-400">
            Register for continuous Zero Trust session protection
          </p>
        </div>

        {error && (
          <ErrorBanner message={error.message} code={error.code} onDismiss={() => setError(null)} />
        )}

        <form className="mt-8 space-y-5" onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div>
              <label htmlFor="signup-email" className={labelClass}>Email Address</label>
              <input
                id="signup-email"
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
              <label htmlFor="signup-password" className={labelClass}>Password</label>
              <input
                id="signup-password"
                name="password"
                type="password"
                autoComplete="new-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={loading}
                className={inputClass}
                placeholder="At least 6 characters"
              />
            </div>
            <div>
              <label htmlFor="signup-confirm" className={labelClass}>Confirm Password</label>
              <input
                id="signup-confirm"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={loading}
                className={inputClass}
                placeholder="Repeat password"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-bold rounded-xl text-white bg-gradient-to-r from-brand-blue via-brand-luminous to-brand-cyan shadow-lg shadow-brand-luminous/30 hover:brightness-110 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-brand-cyan transition-all disabled:opacity-50 hover:scale-[1.01]"
          >
            {loading ? <Spinner size="sm" label="Creating account..." /> : 'Sign Up'}
          </button>
        </form>

        <p className="text-center text-xs text-ink-400 pt-2 border-t border-white/5">
          Already have an account?{' '}
          <Link to="/login" className="font-semibold text-brand-cyan hover:underline underline-offset-4" data-testid="login-link">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}

export default UserSignupPage;
