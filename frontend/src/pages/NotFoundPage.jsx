import React from 'react';
import { Link } from 'react-router-dom';

/**
 * Fallback 404 Not Found page.
 */
export function NotFoundPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full text-center space-y-6 bg-white p-8 rounded-xl shadow-sm border border-gray-100">
        <h1 className="text-4xl font-extrabold text-indigo-600" data-testid="page-title">
          404 - Page Not Found
        </h1>
        <p className="text-sm text-gray-600">
          The requested security dashboard route does not exist.
        </p>
        <div>
          <Link
            to="/login"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Return to Login
          </Link>
        </div>
      </div>
    </div>
  );
}
