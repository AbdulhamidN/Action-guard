import React, { useState, useEffect, useRef, useCallback } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { Spinner } from '../common/Spinner.jsx';

/**
 * StepUpModal provides accessible step-up OTP challenge issuance and verification.
 * Adheres to Zero Trust re-verification requirements:
 * - Traps keyboard focus within the dialog.
 * - Restores focus to the triggering element upon dismissal.
 * - Responds to Escape key for accessible cancellation.
 * - Enforces single-retry invariant for triggering sensitive action upon elevation.
 * - Supports development demo OTP retrieval without exposing credentials.
 *
 * @param {object} props
 * @param {boolean} props.isOpen
 * @param {() => void} props.onClose
 * @param {string} props.scope
 * @param {string} props.sessionId
 * @param {(() => Promise<any>)|null} [props.triggeringAction=null]
 * @param {((result: object) => void)|null} [props.onSuccess=null]
 */
export function StepUpModal({
  isOpen,
  onClose,
  scope = 'sensitive_action',
  sessionId,
  triggeringAction = null,
  onSuccess = null
}) {
  const [challenge, setChallenge] = useState(null);
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState(null);
  const [remainingAttempts, setRemainingAttempts] = useState(null);
  const [remainingSeconds, setRemainingSeconds] = useState(null);
  const [demoCodeLoading, setDemoCodeLoading] = useState(false);

  const modalRef = useRef(null);
  const inputRef = useRef(null);
  const previousActiveElementRef = useRef(null);

  // Capture previous active element when opened, and restore on close
  useEffect(() => {
    if (isOpen) {
      previousActiveElementRef.current = document.activeElement;
    } else {
      if (previousActiveElementRef.current && typeof previousActiveElementRef.current.focus === 'function') {
        previousActiveElementRef.current.focus();
      }
      setChallenge(null);
      setCode('');
      setError(null);
      setRemainingAttempts(null);
      setRemainingSeconds(null);
    }
  }, [isOpen]);

  // Request challenge when opened
  const issueChallenge = useCallback(async () => {
    if (!sessionId || !scope) return;
    setIssuing(true);
    setError(null);
    try {
      const res = await apiRequest(`/sessions/${sessionId}/step-up/challenge`, {
        method: 'POST',
        body: { scope },
        authMode: 'user'
      });
      setChallenge(res);
      setRemainingSeconds(res.ttl_seconds || 300);
      setRemainingAttempts(3);
    } catch (err) {
      setError(err.message || 'Failed to issue verification challenge');
    } finally {
      setIssuing(false);
    }
  }, [sessionId, scope]);

  useEffect(() => {
    if (isOpen && !challenge && !issuing) {
      issueChallenge();
    }
  }, [isOpen, challenge, issuing, issueChallenge]);

  // Focus trap and Escape key listener
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }

      if (e.key === 'Tab') {
        if (!modalRef.current) return;
        const focusableElements = modalRef.current.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        const focusable = Array.prototype.filter.call(
          focusableElements,
          (el) => !el.disabled && el.offsetParent !== null
        );

        if (focusable.length === 0) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Autofocus input when challenge is ready
  useEffect(() => {
    if (isOpen && challenge && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isOpen, challenge]);

  // Countdown timer for challenge expiry
  useEffect(() => {
    if (!challenge || remainingSeconds === null || remainingSeconds <= 0) return;
    const interval = setInterval(() => {
      setRemainingSeconds((prev) => {
        if (prev === null || prev <= 1) {
          clearInterval(interval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [challenge, remainingSeconds]);

  // Fetch demo OTP code if in development / test demo mode
  const handleFetchDemoCode = async () => {
    if (!challenge) return;
    setDemoCodeLoading(true);
    setError(null);
    try {
      const res = await apiRequest(
        `/sessions/${sessionId}/step-up/demo-code?challenge_id=${challenge.challenge_id}`,
        { authMode: 'user' }
      );
      if (res && res.demo_code) {
        setCode(res.demo_code);
      }
    } catch (err) {
      setError('Demo code unavailable: ' + (err.message || 'not in demo mode'));
    } finally {
      setDemoCodeLoading(false);
    }
  };

  const handleVerify = async (e) => {
    e.preventDefault();
    if (!challenge || !code.trim()) return;

    setLoading(true);
    setError(null);
    try {
      // 1. Verify OTP (grants elevation directly on session)
      const verifyRes = await apiRequest(`/sessions/${sessionId}/step-up/verify`, {
        method: 'POST',
        body: {
          challenge_id: challenge.challenge_id,
          code: code.trim()
        },
        authMode: 'user'
      });

      let elevation = verifyRes;
      if (verifyRes && verifyRes.verification_ticket && !verifyRes.elevated) {
        elevation = await apiRequest(`/sessions/${sessionId}/elevate`, {
          method: 'POST',
          body: {
            verification_ticket: verifyRes.verification_ticket,
            scope
          },
          authMode: 'user'
        });
      }

      // 2. Single-retry invariant for triggering action
      let actionResult = null;
      if (typeof triggeringAction === 'function') {
        try {
          actionResult = await triggeringAction();
        } catch (retryErr) {
          console.warn('[StepUpModal] Retrying action after elevation failed:', retryErr);
        }
      }

      if (typeof onSuccess === 'function') {
        onSuccess({
          elevation,
          actionResult
        });
      }

      onClose();
    } catch (err) {
      if (err.details && err.details.remaining_attempts !== undefined) {
        setRemainingAttempts(err.details.remaining_attempts);
      }
      setError(err.message || 'Verification failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-900 bg-opacity-50"
      role="dialog"
      aria-modal="true"
      aria-labelledby="step-up-modal-title"
      ref={modalRef}
      data-testid="step-up-modal"
    >
      <div className="bg-white rounded-lg shadow-xl max-w-md w-full p-6 space-y-5 border border-gray-200">
        <div className="flex items-center justify-between border-b pb-3">
          <div className="flex items-center space-x-2">
            <span className="p-2 bg-indigo-100 text-indigo-700 rounded-full" aria-hidden="true">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            </span>
            <h3 id="step-up-modal-title" className="text-lg font-semibold text-gray-900" data-testid="step-up-title">
              Identity Re-Verification Required
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 rounded"
            aria-label="Close verification modal"
            data-testid="step-up-close-button"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {issuing ? (
          <div className="flex flex-col items-center justify-center py-6 space-y-3" data-testid="step-up-loading">
            <Spinner />
            <p className="text-sm text-gray-600">Generating verification challenge...</p>
          </div>
        ) : (
          <form onSubmit={handleVerify} className="space-y-4">
            <p className="text-sm text-gray-600" data-testid="step-up-instruction">
              To proceed with this sensitive action, enter the 6-digit one-time code sent to your registered email
              {challenge?.masked_destination ? ` (${challenge.masked_destination})` : ''}.
            </p>

            {remainingSeconds !== null && (
              <div className="flex items-center justify-between text-xs text-gray-500 bg-gray-50 p-2 rounded border border-gray-100">
                <span>Verification Scope: <strong className="text-gray-700">{scope}</strong></span>
                <span data-testid="step-up-countdown" className={remainingSeconds < 30 ? 'text-red-600 font-semibold' : ''}>
                  Expires in: {remainingSeconds}s
                </span>
              </div>
            )}

            {error && (
              <div
                className="p-3 bg-red-50 border border-red-200 rounded text-sm text-red-700"
                role="alert"
                data-testid="step-up-error"
              >
                {error}
                {remainingAttempts !== null && remainingAttempts > 0 && (
                  <div className="text-xs mt-1 text-red-600" data-testid="step-up-remaining-attempts">
                    {remainingAttempts} attempt(s) remaining.
                  </div>
                )}
              </div>
            )}

            <div>
              <label htmlFor="step-up-code-input" className="block text-sm font-medium text-gray-700 mb-1">
                One-Time Code (6 digits)
              </label>
              <input
                id="step-up-code-input"
                ref={inputRef}
                type="text"
                pattern="[0-9]*"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 text-center tracking-widest text-lg font-mono"
                disabled={loading || remainingSeconds === 0}
                required
                data-testid="step-up-input"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={handleFetchDemoCode}
                disabled={demoCodeLoading || !challenge}
                className="text-xs text-indigo-600 hover:text-indigo-800 underline focus:outline-none"
                data-testid="step-up-demo-button"
              >
                {demoCodeLoading ? 'Fetching Demo Code...' : 'Get Demo Code (Dev/Test)'}
              </button>

              {remainingSeconds === 0 && (
                <button
                  type="button"
                  onClick={issueChallenge}
                  className="text-xs text-gray-700 hover:text-gray-900 font-medium underline focus:outline-none"
                  data-testid="step-up-resend-button"
                >
                  Request New Code
                </button>
              )}
            </div>

            <div className="flex justify-end space-x-3 pt-3 border-t">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                data-testid="step-up-cancel-button"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || code.length !== 6 || remainingSeconds === 0}
                className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                data-testid="step-up-submit-button"
              >
                {loading && <Spinner className="w-4 h-4 mr-2" />}
                Verify & Proceed
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
