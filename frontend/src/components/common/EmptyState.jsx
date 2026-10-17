import React from 'react';

/**
 * Standard placeholder component for empty data collections and telemetry feeds.
 *
 * @param {{
 *   title?: string,
 *   description?: string
 * }} props
 */
export function EmptyState({
  title = 'No activity recorded',
  description = 'There are currently no events or records to display.'
}) {
  return (
    <div
      className="text-center py-8 px-4 border-2 border-dashed border-gray-200 rounded-lg"
      data-testid="empty-state"
    >
      <svg
        className="mx-auto h-10 w-10 text-gray-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          strokeWidth="1.5"
          d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
        />
      </svg>
      <h3 className="mt-2 text-sm font-medium text-gray-900">{String(title)}</h3>
      <p className="mt-1 text-sm text-gray-500">{String(description)}</p>
    </div>
  );
}
