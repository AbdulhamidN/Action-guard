import React from 'react';

/**
 * Renders error messages safely as plain text to prevent HTML injection.
 *
 * @param {{
 *   message: string,
 *   code?: string,
 *   onDismiss?: () => void
 * }} props
 */
export function ErrorBanner({ message, code, onDismiss }) {
  if (!message) return null;

  return (
    <div
      className="p-4 mb-4 text-sm text-red-800 rounded-lg bg-red-50 border border-red-200 flex items-start justify-between"
      role="alert"
      data-testid="error-banner"
    >
      <div className="flex items-center space-x-2">
        <svg className="w-5 h-5 text-red-600 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
          <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
        </svg>
        <div>
          {code && <span className="font-semibold mr-1">[{String(code)}]</span>}
          <span>{String(message)}</span>
        </div>
      </div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          className="ml-auto -mx-1.5 -my-1.5 bg-red-50 text-red-500 rounded-lg focus:ring-2 focus:ring-red-400 p-1.5 hover:bg-red-100 inline-flex h-8 w-8"
          aria-label="Close error banner"
        >
          <span className="sr-only">Close</span>
          <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </button>
      )}
    </div>
  );
}
