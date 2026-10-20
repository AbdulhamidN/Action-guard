import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';

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
    'appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-sm';
  const labelClass = 'block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-1';

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-md border border-gray-100">
        <div>
          <div className="mx-auto h-12 w-12 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-xl shadow-md">
            AG
          </div>
          <h2 className="mt-6 text-center text-2xl font-extrabold text-gray-900" data-testid="page-title">
            Create Account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Register for ActionGuard Zero Trust protection
          </p>
        </div>

        {error && (
          <ErrorBanner message={error.message} code={error.code} onDismiss={() => setError(null)} />
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm space-y-4">
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
            className="group relative w-full flex justify-center py-2.5 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors shadow-sm disabled:opacity-50"
          >
            {loading ? <Spinner size="sm" label="Creating account..." /> : 'Sign Up'}
          </button>
        </form>

        <p className="text-center text-sm text-gray-600">
          Already have an account?{' '}
          <Link to="/login" className="font-medium text-indigo-600 hover:text-indigo-700" data-testid="login-link">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}

export default UserSignupPage;
