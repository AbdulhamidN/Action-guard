import React, { useState } from 'react';
import { apiRequest } from '../../services/apiClient.js';
import { storeCancellationToken } from '../../services/cancellationStorage.js';
import { Spinner } from '../common/Spinner.jsx';

/**
 * ActionTriggerPanel provides an interactive workbench for demonstrating
 * real Zero Trust security decisions (Allow, Re-verify / Step-Up, Delay, Block).
 *
 * @param {object} props
 * @param {string} props.sessionId
 * @param {(params: { scope: string, sessionId: string, triggeringAction: () => Promise<any> }) => void} props.onStepUpRequired
 * @param {() => void} [props.onActionCompleted]
 */
export function ActionTriggerPanel({ sessionId, onStepUpRequired, onActionCompleted = null }) {
  const [phone, setPhone] = useState('+15551234567');
  const [highImpactOp, setHighImpactOp] = useState('delete_resource');
  const [highImpactTarget, setHighImpactTarget] = useState('production_database_replica');
  const [loadingAction, setLoadingAction] = useState(null);
  const [actionResult, setActionResult] = useState(null);
  const [errorResult, setErrorResult] = useState(null);

  const handleUpdatePhone = async () => {
    setLoadingAction('phone');
    setActionResult(null);
    setErrorResult(null);
    try {
      const res = await apiRequest('/account/phone', {
        method: 'POST',
        body: { phone_number: phone },
        authMode: 'user'
      });
      setActionResult({
        type: 'allow',
        title: 'Action Allowed & Completed',
        message: `Phone number updated successfully to ${phone}. Zero Trust policy evaluated this as low/medium risk.`,
        data: res
      });
      if (typeof onActionCompleted === 'function') {
        onActionCompleted();
      }
    } catch (err) {
      handleActionError(err, () => handleUpdatePhone());
    } finally {
      setLoadingAction(null);
    }
  };

  const handleHighImpactAction = async () => {
    setLoadingAction('high_impact');
    setActionResult(null);
    setErrorResult(null);
    try {
      const res = await apiRequest('/account/high-impact', {
        method: 'POST',
        body: { operation: highImpactOp, target: highImpactTarget },
        authMode: 'user'
      });
      setActionResult({
        type: 'allow',
        title: 'Action Completed (Elevated)',
        message: `Critical operation '${highImpactOp}' completed successfully under active elevation.`,
        data: res
      });
      if (typeof onActionCompleted === 'function') {
        onActionCompleted();
      }
    } catch (err) {
      handleActionError(err, () => handleHighImpactAction());
    } finally {
      setLoadingAction(null);
    }
  };

  const handleActionError = (err, retryFn) => {
    if (err.status === 403 && err.code === 'step_up_required') {
      const scope = err.details?.required_scope || 'sensitive_action';
      if (typeof onStepUpRequired === 'function') {
        onStepUpRequired({
          scope,
          sessionId,
          triggeringAction: retryFn
        });
      }
      return;
    }

    if (err.status === 403 && err.code === 'action_delayed') {
      const details = err.details || {};
      const actionId = details.pending_action_id || details.decision_id;
      const cancellationToken = details.cancellation_token;

      if (actionId && cancellationToken) {
        storeCancellationToken(actionId, cancellationToken);
      }

      setErrorResult({
        type: 'delay',
        title: 'Action Delayed (Cooling-Off Period Triggered)',
        message: err.message || 'Action is currently delayed. Check the Delayed Actions tab.',
        details
      });
      if (typeof onActionCompleted === 'function') {
        onActionCompleted();
      }
      return;
    }

    if (err.status === 403 && (err.code === 'action_blocked' || err.code === 'session_contained')) {
      setErrorResult({
        type: 'block',
        title: 'Action Blocked by Zero Trust Policy',
        message: err.message || 'This action has been blocked due to high evaluated risk.',
        details: err.details
      });
      return;
    }

    setErrorResult({
      type: 'error',
      title: 'Action Failed',
      message: err.message || 'An unexpected error occurred.',
      details: err.details
    });
  };

  return (
    <div className="bg-white shadow rounded-lg border border-gray-200 p-6 space-y-6" data-testid="action-trigger-panel">
      <div>
        <h3 className="text-lg font-medium text-gray-900" data-testid="action-panel-title">
          Security Action Playground & Policy Demonstration
        </h3>
        <p className="text-sm text-gray-500">
          Trigger sensitive operations to experience how Zero Trust evaluates risk, enforces step-up re-verification, delays actions, and responds proportionally.
        </p>
      </div>

      {actionResult && (
        <div
          className="p-4 bg-green-50 border border-green-200 rounded-md text-sm text-green-800 space-y-1"
          role="status"
          data-testid="action-success-alert"
        >
          <div className="font-semibold">{actionResult.title}</div>
          <div>{actionResult.message}</div>
        </div>
      )}

      {errorResult && (
        <div
          className={`p-4 rounded-md text-sm space-y-1 border ${
            errorResult.type === 'delay'
              ? 'bg-amber-50 border-amber-200 text-amber-800'
              : 'bg-red-50 border-red-200 text-red-800'
          }`}
          role="alert"
          data-testid="action-error-alert"
        >
          <div className="font-semibold">{errorResult.title}</div>
          <div>{errorResult.message}</div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-2">
        {/* Action 1: Standard Medium-Sensitivity Action (Allow) */}
        <div className="p-4 rounded-lg border border-gray-200 bg-gray-50 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-900">Standard Action (Allow)</span>
              <span className="text-xs px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 font-medium">
                Expected: Allow
              </span>
            </div>
            <p className="text-xs text-gray-600">
              Updates your account phone number (medium sensitivity). Under standard low-risk conditions, this action is allowed without step-up.
            </p>
            <div>
              <label htmlFor="input-phone" className="block text-xs font-medium text-gray-700 mb-1">
                Phone Number (E.164)
              </label>
              <input
                id="input-phone"
                type="text"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                className="w-full text-xs px-3 py-2 border border-gray-300 rounded focus:outline-none focus:ring-indigo-500 font-mono"
                data-testid="input-phone"
              />
            </div>
          </div>
          <button
            type="button"
            onClick={handleUpdatePhone}
            disabled={loadingAction === 'phone'}
            className="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
            data-testid="btn-update-phone"
          >
            {loadingAction === 'phone' && <Spinner className="w-3.5 h-3.5 mr-2" />}
            Execute Action (Update Phone)
          </button>
        </div>

        {/* Action 2: Critical Sensitive Action (Step-Up / Re-verify) */}
        <div className="p-4 rounded-lg border border-gray-200 bg-gray-50 flex flex-col justify-between space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-semibold text-gray-900">Critical Action (Re-Verify)</span>
              <span className="text-xs px-2 py-0.5 rounded bg-amber-100 text-amber-800 font-medium">
                Expected: Re-Verify
              </span>
            </div>
            <p className="text-xs text-gray-600">
              Executes a high-impact infrastructure mutation (critical sensitivity). Requires valid step-up elevation before proceeding.
            </p>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label htmlFor="input-operation" className="block text-xs font-medium text-gray-700 mb-1">
                  Operation
                </label>
                <input
                  id="input-operation"
                  type="text"
                  value={highImpactOp}
                  onChange={(e) => setHighImpactOp(e.target.value)}
                  className="w-full text-xs px-3 py-2 border border-gray-300 rounded focus:outline-none font-mono"
                  data-testid="input-operation"
                />
              </div>
              <div>
                <label htmlFor="input-target" className="block text-xs font-medium text-gray-700 mb-1">
                  Target Resource
                </label>
                <input
                  id="input-target"
                  type="text"
                  value={highImpactTarget}
                  onChange={(e) => setHighImpactTarget(e.target.value)}
                  className="w-full text-xs px-3 py-2 border border-gray-300 rounded focus:outline-none font-mono"
                  data-testid="input-target"
                />
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={handleHighImpactAction}
            disabled={loadingAction === 'high_impact'}
            className="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent shadow-sm text-xs font-medium rounded text-white bg-amber-600 hover:bg-amber-700 focus:outline-none focus:ring-2 focus:ring-amber-500 disabled:opacity-50"
            data-testid="btn-high-impact"
          >
            {loadingAction === 'high_impact' && <Spinner className="w-3.5 h-3.5 mr-2" />}
            Execute Sensitive Action
          </button>
        </div>
      </div>
    </div>
  );
}
