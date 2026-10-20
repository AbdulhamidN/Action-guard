import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { apiRequest, ApiError } from '../services/apiClient.js';
import { setUserToken } from '../services/authStorage.js';
import { getDeviceFingerprint } from '../services/fingerprint.js';
import { ErrorBanner } from '../components/common/ErrorBanner.jsx';
import { Spinner } from '../components/common/Spinner.jsx';

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

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-md border border-gray-100">
        <div>
          <div className="mx-auto h-12 w-12 bg-indigo-600 rounded-xl flex items-center justify-center text-white font-bold text-xl shadow-md">
            AG
          </div>
          <h2 className="mt-6 text-center text-2xl font-extrabold text-gray-900" data-testid="page-title">
            User Login
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            ActionGuard Zero Trust User Session Authentication
          </p>
        </div>

        {justRegistered && !error && (
          <div className="rounded-md bg-emerald-50 border border-emerald-200 p-3 text-sm text-emerald-800" data-testid="registered-notice">
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

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="rounded-md shadow-sm space-y-4">
            <div>
              <label htmlFor="user-email" className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-1">
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
                className="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                placeholder="user@example.com"
              />
            </div>

            <div>
              <label htmlFor="user-password" className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-1">
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
                className="appearance-none rounded-lg relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-400 text-gray-900 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-sm"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2.5 px-4 border border-transparent text-sm font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors shadow-sm disabled:opacity-50"
            >
              {loading ? <Spinner size="sm" label="Authenticating..." /> : 'Sign In'}
            </button>
          </div>
        </form>

        <p className="text-center text-sm text-gray-600">
          No account yet?{' '}
          <Link to="/signup" className="font-medium text-indigo-600 hover:text-indigo-700" data-testid="signup-link">
            Sign up
          </Link>
        </p>
      </div>
    </div>
  );
}
