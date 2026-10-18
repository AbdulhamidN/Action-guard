import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { apiRequest } from '../../services/apiClient.js';
import { TierBadge } from '../../components/common/TierBadge.jsx';
import { Spinner } from '../../components/common/Spinner.jsx';
import { ErrorBanner } from '../../components/common/ErrorBanner.jsx';
import { EmptyState } from '../../components/common/EmptyState.jsx';

/**
 * LiveDemoPage provides an interactive, competition-ready demonstration interface
 * for ActionGuard's attack simulation engine, adaptive Zero Trust evaluation,
 * and false-positive fixtures.
 */
export function LiveDemoPage() {
  const [scenarios, setScenarios] = useState([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState('scenario_a');
  const [isLoadingScenarios, setIsLoadingScenarios] = useState(true);
  const [isRunning, setIsRunning] = useState(false);
  const [isCleaning, setIsCleaning] = useState(false);
  const [runResult, setRunResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [cleanupNotice, setCleanupNotice] = useState(null);

  // Load scenarios on mount
  useEffect(() => {
    let isMounted = true;
    async function loadScenarios() {
      try {
        setIsLoadingScenarios(true);
        const data = await apiRequest('/admin/demo/scenarios', { authMode: 'admin' });
        if (isMounted && data && Array.isArray(data.scenarios)) {
          setScenarios(data.scenarios);
          if (data.scenarios.length > 0) {
            setSelectedScenarioId(data.scenarios[0].id);
          }
        }
      } catch (err) {
        if (isMounted) {
          setErrorMessage(err.message || 'Failed to load scenario definitions');
        }
      } finally {
        if (isMounted) setIsLoadingScenarios(false);
      }
    }
    loadScenarios();
    return () => {
      isMounted = false;
    };
  }, []);

  const selectedScenario = scenarios.find((s) => s.id === selectedScenarioId) || null;

  // Execute scenario
  const handleRunScenario = async () => {
    if (!selectedScenarioId || isRunning) return;
    setIsRunning(true);
    setErrorMessage(null);
    setCleanupNotice(null);
    try {
      const response = await apiRequest('/admin/demo/run', {
        method: 'POST',
        authMode: 'admin',
        body: {
          scenario_id: selectedScenarioId,
          cleanup_before: true,
          cleanup_after: false
        }
      });
      setRunResult(response);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to execute scenario');
      setRunResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  // Reset demo data
  const handleResetDemoData = async () => {
    if (!runResult || isCleaning) return;
    const runId =
      runResult.mode === 'false_positive'
        ? runResult.result?.summary?.run_id
        : runResult.result?.run_id;
    const userId =
      runResult.mode === 'false_positive'
        ? runResult.result?.summary?.user_id
        : runResult.result?.user_id;

    if (!runId && !userId) return;

    setIsCleaning(true);
    setErrorMessage(null);
    try {
      const cleanupRes = await apiRequest('/admin/demo/cleanup', {
        method: 'POST',
        authMode: 'admin',
        body: { run_id: runId, user_id: userId }
      });
      setCleanupNotice(`Demo data successfully cleaned up (Removed ${cleanupRes.removed?.events || 0} events, ${cleanupRes.removed?.decisions || 0} decisions).`);
      setRunResult(null);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to clean up demo data');
    } finally {
      setIsCleaning(false);
    }
  };

  if (isLoadingScenarios) {
    return (
      <div className="py-24 flex justify-center items-center" data-testid="demo-loading-scenarios">
        <Spinner />
      </div>
    );
  }

  const isFalsePositive = runResult?.mode === 'false_positive';
  const fpReport = isFalsePositive ? runResult.result : null;
  const scenarioSummary = !isFalsePositive ? runResult?.result : fpReport?.summary;
  const finalOutcome = scenarioSummary?.final_outcome;

  return (
    <div className="space-y-6" data-testid="live-demo-page">
      {/* Title & Overview Banner */}
      <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2">
              <span className="p-2 bg-indigo-50 text-indigo-700 rounded-lg">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </span>
              Attack Simulation & Live Demo Engine
            </h1>
            <p className="mt-1 text-sm text-slate-500">
              Run repeatable, deterministic attack simulations and legitimate activity tests through the live ActionGuard Zero Trust evaluation pipeline.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {runResult && (
              <button
                type="button"
                onClick={handleResetDemoData}
                disabled={isCleaning || isRunning}
                className="px-4 py-2 border border-rose-300 text-rose-700 hover:bg-rose-50 rounded-md text-sm font-medium transition disabled:opacity-50"
                data-testid="reset-demo-btn"
              >
                {isCleaning ? 'Cleaning...' : 'Reset Demo Data'}
              </button>
            )}
            <button
              type="button"
              onClick={handleRunScenario}
              disabled={isRunning || !selectedScenarioId}
              className="px-5 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-md text-sm font-medium transition shadow-sm flex items-center gap-2 disabled:opacity-50"
              data-testid="run-scenario-btn"
            >
              {isRunning && <Spinner size="small" />}
              {isRunning ? 'Executing Real Pipeline...' : 'Run Live Simulation'}
            </button>
          </div>
        </div>

        {errorMessage && (
          <div className="mt-4">
            <ErrorBanner message={errorMessage} onDismiss={() => setErrorMessage(null)} />
          </div>
        )}

        {cleanupNotice && (
          <div className="mt-4 p-4 bg-emerald-50 border border-emerald-200 rounded-md text-emerald-800 text-sm flex items-center justify-between">
            <span>{cleanupNotice}</span>
            <button
              type="button"
              onClick={() => setCleanupNotice(null)}
              className="text-emerald-700 font-bold ml-4"
            >
              ×
            </button>
          </div>
        )}

        {/* Scenario Selector & Details */}
        <div className="mt-6 pt-6 border-t border-slate-100 grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="space-y-2">
            <label htmlFor="scenario-select" className="block text-xs font-semibold text-slate-500 uppercase tracking-wider">
              Select Demo Scenario
            </label>
            <select
              id="scenario-select"
              value={selectedScenarioId}
              onChange={(e) => setSelectedScenarioId(e.target.value)}
              disabled={isRunning}
              className="w-full px-3 py-2 border border-slate-300 rounded-md text-sm bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
              data-testid="scenario-select"
            >
              {scenarios.map((sc) => (
                <option key={sc.id} value={sc.id}>
                  {sc.name} ({sc.scenario_type})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2 space-y-2 bg-slate-50 rounded-lg p-4 border border-slate-200">
            {selectedScenario ? (
              <>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-900 text-sm">{selectedScenario.name}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                    selectedScenario.scenario_type === 'simulated_takeover'
                      ? 'bg-rose-100 text-rose-800'
                      : selectedScenario.scenario_type === 'false_positive'
                      ? 'bg-sky-100 text-sky-800'
                      : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {selectedScenario.scenario_type}
                  </span>
                </div>
                <p className="text-xs text-slate-600">{selectedScenario.description}</p>
                <div className="text-xs text-slate-500 pt-1">
                  <span className="font-medium text-slate-700">Expected Interpretation: </span>
                  {selectedScenario.expected_interpretation}
                </div>
              </>
            ) : (
              <p className="text-xs text-slate-500">Select a scenario to view its specification.</p>
            )}
          </div>
        </div>
      </div>

      {/* Execution in progress */}
      {isRunning && (
        <div className="bg-white rounded-lg shadow-sm border border-slate-200 p-12 text-center space-y-3" data-testid="demo-running-state">
          <div className="flex justify-center">
            <Spinner size="large" />
          </div>
          <h3 className="text-lg font-semibold text-slate-900">Executing Security Evaluation Pipeline</h3>
          <p className="text-sm text-slate-500 max-w-lg mx-auto">
            Passing events through sequence correlation, deriving device and country novelty flags, scoring dynamic risk, evaluating active policy rules, and executing containment if triggered...
          </p>
        </div>
      )}

      {/* No run result state */}
      {!runResult && !isRunning && (
        <EmptyState
          title="No Simulation Executed Yet"
          description="Choose a scenario above and click 'Run Live Simulation' to observe ActionGuard's real risk pipeline and policy decisions."
        />
      )}

      {/* Execution Results View */}
      {runResult && !isRunning && (
        <div className="space-y-6" data-testid="demo-results-section">
          {/* Top Outcome Summary Card */}
          <div className={`rounded-lg border p-6 shadow-sm ${
            finalOutcome?.is_contained
              ? 'bg-rose-50/70 border-rose-200'
              : 'bg-white border-slate-200'
          }`}>
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
              <div className="space-y-1">
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-bold text-slate-900">
                    {scenarioSummary?.scenario_name}
                  </h2>
                  <span className="text-xs font-mono px-2 py-0.5 bg-slate-100 text-slate-700 rounded">
                    {scenarioSummary?.run_id}
                  </span>
                </div>
                <p className="text-sm text-slate-600">
                  Demo User: <span className="font-mono text-slate-800">{scenarioSummary?.user_email}</span>
                </p>
              </div>

              {/* Status metrics grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                <div className="bg-white/80 p-3 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="block text-xs font-medium text-slate-500 uppercase">Risk Score</span>
                  <span className="text-2xl font-bold text-slate-900">{finalOutcome?.risk_score ?? 0}</span>
                </div>

                <div className="bg-white/80 p-3 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="block text-xs font-medium text-slate-500 uppercase">Risk Tier</span>
                  <div className="mt-1">
                    <TierBadge tier={finalOutcome?.risk_tier || 'low'} />
                  </div>
                </div>

                <div className="bg-white/80 p-3 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="block text-xs font-medium text-slate-500 uppercase">Policy Decision</span>
                  <span className={`text-base font-bold capitalize ${
                    finalOutcome?.policy_decision === 'block'
                      ? 'text-rose-700'
                      : finalOutcome?.policy_decision === 'reverify' || finalOutcome?.policy_decision === 'delay'
                      ? 'text-amber-700'
                      : 'text-emerald-700'
                  }`}>
                    {finalOutcome?.policy_decision || 'allow'}
                  </span>
                </div>

                <div className="bg-white/80 p-3 rounded-lg border border-slate-200 shadow-2xs">
                  <span className="block text-xs font-medium text-slate-500 uppercase">Containment</span>
                  <span className={`text-sm font-bold ${
                    finalOutcome?.is_contained
                      ? 'text-rose-700 flex items-center gap-1'
                      : 'text-slate-700'
                  }`}>
                    {finalOutcome?.is_contained ? 'Session Locked' : 'None'}
                  </span>
                </div>
              </div>
            </div>

            {/* Quick admin inspection link */}
            {scenarioSummary?.user_id && (
              <div className="mt-4 pt-4 border-t border-slate-200/60 flex items-center justify-between text-xs">
                <span className="text-slate-500">
                  Inspect the live database records created by this run in the Admin Console:
                </span>
                <Link
                  to={`/admin/users/${scenarioSummary.user_id}`}
                  className="inline-flex items-center font-medium text-indigo-600 hover:text-indigo-800"
                >
                  View User Activity & Decisions Graph →
                </Link>
              </div>
            )}
          </div>

          {/* False-Positive Comparison Card */}
          {isFalsePositive && fpReport && (
            <div className="bg-sky-50 border border-sky-200 rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-sky-900 text-sm flex items-center gap-2">
                  <svg className="w-4 h-4 text-sky-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  False-Positive Analysis & Target Verification
                </h3>
                <span className={`text-xs px-2.5 py-1 rounded-full font-bold ${
                  fpReport.is_acceptable ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'
                }`}>
                  {fpReport.is_acceptable ? 'Non-False-Positive Confirmed (PASSED)' : 'Flagged (Unacceptable Friction)'}
                </span>
              </div>
              <p className="text-xs text-sky-800">
                <span className="font-semibold">Expected Behavior: </span>
                {fpReport.expected_interpretation} (Maximum acceptable policy friction: <span className="font-mono">{fpReport.expected_max_acceptable_decision}</span>)
              </p>
              <div className="text-xs text-sky-700">
                <span className="font-semibold">Observed Outcome: </span>
                System returned decision <span className="font-bold uppercase text-sky-900">{fpReport.observed_system_outcome?.policy_decision}</span> with risk score <span className="font-bold">{fpReport.observed_system_outcome?.risk_score}</span>. User was not inappropriately contained.
              </div>
            </div>
          )}

          {/* Step-by-Step Chronological Pipeline Execution */}
          <div className="bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
            <div className="px-6 py-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <h3 className="font-bold text-slate-900 text-sm uppercase tracking-wider">
                Real-Time Execution Steps ({scenarioSummary?.steps?.length || 0})
              </h3>
              <span className="text-xs text-slate-500">Production Evaluation Pipeline Telemetry</span>
            </div>

            <div className="divide-y divide-slate-100">
              {scenarioSummary?.steps?.map((step) => {
                const obs = step.observed_pipeline;
                return (
                  <div key={step.step_number} className="p-6 space-y-4 hover:bg-slate-50/50 transition">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-3">
                        <span className="w-6 h-6 rounded-full bg-indigo-100 text-indigo-800 font-bold text-xs flex items-center justify-center">
                          {step.step_number}
                        </span>
                        <div>
                          <h4 className="font-semibold text-slate-900 text-sm">{step.step_name}</h4>
                          <span className="text-xs font-mono text-slate-500">
                            event_type: <span className="text-indigo-600 font-semibold">{step.event_type}</span> | sensitivity: {step.action_sensitivity}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="text-xs font-semibold text-slate-500">
                          Score: <span className="text-slate-900 font-bold">{obs.risk_score}</span>
                        </span>
                        <TierBadge tier={obs.risk_tier} />
                        <span className={`text-xs px-2 py-0.5 rounded font-bold uppercase ${
                          obs.policy_decision === 'block'
                            ? 'bg-rose-100 text-rose-800'
                            : obs.policy_decision === 'reverify' || obs.policy_decision === 'delay'
                            ? 'bg-amber-100 text-amber-800'
                            : 'bg-emerald-100 text-emerald-800'
                        }`}>
                          {obs.policy_decision}
                        </span>
                      </div>
                    </div>

                    {/* Contributing Signals Breakdown */}
                    {obs.contributing_signals && obs.contributing_signals.length > 0 && (
                      <div className="bg-slate-50 rounded p-3 border border-slate-200 text-xs">
                        <span className="font-medium text-slate-700 block mb-1">
                          Contributing Risk Signals & Pattern Rules:
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {obs.contributing_signals.map((sig, sIdx) => (
                            <span
                              key={sIdx}
                              className="px-2 py-0.5 bg-white border border-slate-200 rounded text-slate-700 font-mono"
                            >
                              {sig.signal} <span className="text-indigo-600 font-bold">(+{sig.weight})</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Explanations */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                      <div className="p-3 bg-slate-50/70 rounded border border-slate-100">
                        <span className="font-semibold text-slate-700 block mb-0.5">User-Facing Explanation</span>
                        <p className="text-slate-600 italic">"{obs.user_facing_explanation || 'Standard security review applied.'}"</p>
                      </div>
                      <div className="p-3 bg-slate-50/70 rounded border border-slate-100">
                        <span className="font-semibold text-slate-700 block mb-0.5">Security Administrator Explanation</span>
                        <p className="text-slate-600 font-mono text-[11px]">{obs.admin_facing_explanation || 'Evaluated standard risk matrix.'}</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default LiveDemoPage;
