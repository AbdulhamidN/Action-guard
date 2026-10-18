'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const {
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ActionSequence
} = require('../database/models');
const { recordSecurityEvent } = require('../services/eventService');
const { createSession } = require('../services/sessionService');
const { getOrCreateDevice } = require('../services/deviceService');
const policyLoader = require('../services/policyLoader');
const { decide, SENSITIVITY_RANKS } = require('../utils/policyDecision');
const {
  shouldTriggerContainmentForDecision,
  containSessionAndLockAccount
} = require('../services/containmentService');
const { getScenarioDefinition } = require('./definitions');
const { cleanupScenarioRun } = require('./cleanup');

const DEFAULT_DEMO_PASSWORD = 'DemoUserPassword123!';

/**
 * Executes a deterministic security scenario through the real ActionGuard evaluation pipeline.
 *
 * Guarantees:
 * 1. Exercises the actual production pipeline (events, sequence correlation, risk scoring, PDP, containment).
 * 2. Never hardcodes or predetermines risk scores or policy outcomes.
 * 3. Uses isolated, run-scoped demo identities.
 * 4. Never prints or stores plaintext passwords, raw device fingerprints, or JWTs.
 * 5. Safe and repeatable: cleans up prior run data if re-executed with the same run identifier.
 *
 * @param {string} scenarioId - Scenario identifier (e.g. 'scenario_a', 'scenario_b')
 * @param {object} [options={}]
 * @param {string} [options.runId] - Optional explicit run identifier
 * @param {boolean} [options.cleanupBefore=true] - Clean up any existing data for runId before execution
 * @param {boolean} [options.cleanupAfter=false] - Automatically clean up data after execution completes
 * @param {Date} [options.baseTimestamp] - Base reference timestamp for the scenario
 * @returns {Promise<object>} Structured execution summary
 */
async function runScenario(scenarioId, options = {}) {
  const scenario = getScenarioDefinition(scenarioId);
  if (!scenario) {
    throw new Error(
      `[ScenarioRunner] Unknown scenario identifier: '${scenarioId}'. Use definitions to view available scenarios.`
    );
  }

  const runId =
    options.runId ||
    `run_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  // 1. Safe cleanup before running to guarantee idempotence and avoid duplicate records
  if (options.cleanupBefore !== false) {
    await cleanupScenarioRun({ runId });
  }

  const baseTimestamp = options.baseTimestamp
    ? new Date(options.baseTimestamp)
    : new Date();

  // Resource tracking for run ownership
  const resourcesCreated = {
    userId: null,
    sessionIds: [],
    eventIds: [],
    assessmentIds: [],
    decisionIds: [],
    sequenceIds: [],
    deviceIds: []
  };

  const stepsSummary = [];
  let currentSession = null;
  let isContained = false;

  try {
    // 2. Create isolated demo user
    const demoEmail = `demo-${scenario.id}-${runId}@demo.actionguard.local`;
    const passwordHash = await bcrypt.hash(DEFAULT_DEMO_PASSWORD, 10);

    const user = await User.create({
      email: demoEmail,
      password_hash: passwordHash
    });
    resourcesCreated.userId = user.id;

    // 3. Process baseline events if specified in scenario definition
    if (Array.isArray(scenario.baseline_events) && scenario.baseline_events.length > 0) {
      for (let i = 0; i < scenario.baseline_events.length; i++) {
        const bStep = scenario.baseline_events[i];
        const stepTime = new Date(baseTimestamp.getTime() + bStep.time_offset_ms);

        // Pre-register device if fingerprint is present
        if (bStep.context && bStep.context.device_fingerprint) {
          try {
            const dev = await getOrCreateDevice(user.id, bStep.context.device_fingerprint);
            if (dev && !resourcesCreated.deviceIds.includes(dev.id)) {
              resourcesCreated.deviceIds.push(dev.id);
            }
          } catch {
            // Safe fallback
          }
        }

        let bSessionId = null;
        if (bStep.event_type === 'login_success') {
          const sess = await createSession(user.id, user.email, 3600, bStep.context || {});
          bSessionId = sess.sessionId;
          resourcesCreated.sessionIds.push(sess.sessionId);
        }

        const bEvent = await recordSecurityEvent({
          userId: user.id,
          sessionId: bSessionId,
          eventType: bStep.event_type,
          timestamp: stepTime,
          context: bStep.context || {},
          metadata: bStep.metadata || {}
        });

        resourcesCreated.eventIds.push(bEvent.event_id);
        if (bEvent._assessment && bEvent._assessment.id) {
          resourcesCreated.assessmentIds.push(bEvent._assessment.id);
        }
      }
    }

    // 4. Execute scenario steps in chronological order through the real pipeline
    for (let sIdx = 0; sIdx < scenario.steps.length; sIdx++) {
      const step = scenario.steps[sIdx];
      const stepTime = new Date(baseTimestamp.getTime() + step.time_offset_ms);

      // Handle device registration
      if (step.context && step.context.device_fingerprint) {
        try {
          const dev = await getOrCreateDevice(user.id, step.context.device_fingerprint);
          if (dev && !resourcesCreated.deviceIds.includes(dev.id)) {
            resourcesCreated.deviceIds.push(dev.id);
          }
        } catch {
          // Safe fallback
        }
      }

      // Handle login_success: create real active session
      if (step.event_type === 'login_success') {
        const sess = await createSession(user.id, user.email, 1800, step.context || {});
        currentSession = sess;
        resourcesCreated.sessionIds.push(sess.sessionId);
      }

      const activeSessionId = currentSession ? currentSession.sessionId : null;
      const routeSensitivity =
        (step.metadata && step.metadata.action_sensitivity) || 'medium';

      // Record security event through production eventService pipeline
      // This automatically:
      // - Correlates into ActionSequence & SequenceEvent
      // - Runs evaluateAndStoreRiskForEvent in riskEngineService
      // - Persists RiskAssessment in MySQL
      const eventRecord = await recordSecurityEvent({
        userId: user.id,
        sessionId: activeSessionId,
        eventType: step.event_type,
        timestamp: stepTime,
        context: step.context || {},
        metadata: {
          ...(step.metadata || {}),
          action_status: 'attempted'
        }
      });

      resourcesCreated.eventIds.push(eventRecord.event_id);

      // Retrieve actual real assessment calculated by the risk engine
      let assessmentRecord = eventRecord._assessment || null;
      if (!assessmentRecord) {
        assessmentRecord = await RiskAssessment.findOne({
          where: { event_id: eventRecord.event_id },
          order: [['id', 'DESC']]
        });
      }

      if (assessmentRecord && !resourcesCreated.assessmentIds.includes(assessmentRecord.id)) {
        resourcesCreated.assessmentIds.push(assessmentRecord.id);
      }

      const isRiskAvailable = Boolean(assessmentRecord && assessmentRecord.risk_tier);
      const effectiveRiskScore = isRiskAvailable ? assessmentRecord.risk_score : 100;
      const effectiveRiskTier = isRiskAvailable ? assessmentRecord.risk_tier : 'critical';
      const contributingSignals = isRiskAvailable
        ? assessmentRecord.contributing_signals || []
        : [];
      const signalNames = contributingSignals.map((s) => s.signal);

      // 5. Evaluate policy decision against activePolicy snapshot using PDP decide
      const activePolicy = policyLoader.getActivePolicy();
      const policyVersion = `${activePolicy.policy_id}@${activePolicy.schema_version}`;

      const decisionInput = {
        risk: isRiskAvailable
          ? {
              status: 'ok',
              risk_tier: assessmentRecord.risk_tier,
              signal_names: signalNames
            }
          : {
              status: 'unavailable',
              risk_tier: null,
              signal_names: []
            },
        action: {
          event_type: step.event_type,
          provided_sensitivity: routeSensitivity
        }
      };

      const pdpResult = decide(decisionInput, activePolicy);
      const recommendedDecision = pdpResult.decision;
      const enforcementMode = pdpResult.enforcement_mode || 'automatic';

      let effectiveDecision = recommendedDecision;
      let enforcementOutcome = 'allowed';
      let actionStatus = 'authorized';

      if (effectiveDecision === 'allow') {
        enforcementOutcome = 'allowed';
        actionStatus = 'authorized';
      } else if (effectiveDecision === 'monitor') {
        enforcementOutcome = 'monitored';
        actionStatus = 'authorized';
      } else if (effectiveDecision === 'reverify') {
        enforcementOutcome = 'step_up_challenged';
        actionStatus = 'halted';
      } else if (effectiveDecision === 'delay') {
        enforcementOutcome = 'delayed';
        actionStatus = 'halted';
      } else if (effectiveDecision === 'block') {
        enforcementOutcome = 'blocked';
        actionStatus = 'halted';
      }

      // Check containment eligibility for critical/high block
      let containmentCheck = { qualifies: false, reason: null };
      if (effectiveDecision === 'block') {
        containmentCheck = shouldTriggerContainmentForDecision({
          effectiveDecision: 'block',
          riskTier: effectiveRiskTier,
          reasons: pdpResult.reasons
        });
      }

      // 6. Durably persist PolicyDecision record
      const decisionRecord = await PolicyDecision.create({
        event_id: eventRecord.event_id,
        risk_assessment_id: assessmentRecord ? assessmentRecord.id : null,
        user_id: user.id,
        session_id: activeSessionId,
        action_type: step.event_type,
        action_sensitivity: routeSensitivity,
        risk_score: effectiveRiskScore,
        risk_tier: effectiveRiskTier,
        recommended_decision: recommendedDecision,
        effective_decision: effectiveDecision,
        enforcement_outcome: enforcementOutcome,
        enforcement_mode: enforcementMode,
        policy_version: policyVersion,
        reasons: pdpResult.reasons || [],
        contributing_signals: contributingSignals,
        explanation: pdpResult.explanation || {
          user_facing: '',
          admin_facing: ''
        },
        decided_at: stepTime
      });

      resourcesCreated.decisionIds.push(decisionRecord.id);

      // 7. If containment qualifies, execute real containment
      if (containmentCheck.qualifies) {
        try {
          const containmentResult = await containSessionAndLockAccount({
            userId: user.id,
            sessionId: activeSessionId,
            reason: containmentCheck.reason || 'critical_risk_action_blocked',
            triggeringEventId: eventRecord.event_id,
            triggeringDecisionId: decisionRecord.id,
            context: step.context || {}
          });

          if (containmentResult.session_contained && containmentResult.account_locked) {
            enforcementOutcome = 'contained_and_blocked';
            isContained = true;
            await decisionRecord.update({ enforcement_outcome: 'contained_and_blocked' });
          }
        } catch (cErr) {
          console.warn('[ScenarioRunner] Containment execution failed:', cErr.message);
        }
      }

      // 8. Update SecurityEvent metadata with decision and enforcement outcome
      await eventRecord.update({
        metadata: {
          ...(eventRecord.metadata || {}),
          action_sensitivity: routeSensitivity,
          action_status: actionStatus,
          decision_id: decisionRecord.id,
          effective_decision: effectiveDecision,
          enforcement_outcome: enforcementOutcome,
          policy_version: policyVersion
        }
      });

      // Record step summary
      stepsSummary.push({
        step_number: step.step_number || sIdx + 1,
        step_name: step.name || `${step.event_type} (${routeSensitivity})`,
        event_type: step.event_type,
        timestamp: stepTime.toISOString(),
        action_sensitivity: routeSensitivity,
        observed_pipeline: {
          event_id: eventRecord.event_id,
          risk_score: effectiveRiskScore,
          risk_tier: effectiveRiskTier,
          contributing_signals: contributingSignals,
          policy_decision: effectiveDecision,
          enforcement_outcome: enforcementOutcome,
          reasons: pdpResult.reasons || [],
          user_facing_explanation:
            (pdpResult.explanation && pdpResult.explanation.user_facing) || '',
          admin_facing_explanation:
            (pdpResult.explanation && pdpResult.explanation.admin_facing) || ''
        }
      });
    }

    // Capture user sequences created
    const sequences = await ActionSequence.findAll({
      attributes: ['id'],
      where: { user_id: user.id }
    });
    resourcesCreated.sequenceIds = sequences.map((s) => s.id);

    const lastStep = stepsSummary[stepsSummary.length - 1];

    const executionSummary = {
      scenario_id: scenario.id,
      scenario_name: scenario.name,
      scenario_type: scenario.scenario_type,
      run_id: runId,
      user_id: user.id,
      user_email: demoEmail,
      started_at: baseTimestamp.toISOString(),
      completed_at: new Date().toISOString(),
      steps_executed: stepsSummary.length,
      steps: stepsSummary,
      final_outcome: {
        risk_score: lastStep ? lastStep.observed_pipeline.risk_score : 0,
        risk_tier: lastStep ? lastStep.observed_pipeline.risk_tier : 'low',
        policy_decision: lastStep ? lastStep.observed_pipeline.policy_decision : 'allow',
        enforcement_outcome: lastStep ? lastStep.observed_pipeline.enforcement_outcome : 'allowed',
        is_contained: isContained
      },
      resources_created: resourcesCreated
    };

    if (options.cleanupAfter === true) {
      await cleanupScenarioRun(executionSummary);
      executionSummary.cleaned_up = true;
    }

    return executionSummary;
  } catch (error) {
    // On unexpected error, clean up resources created during partial execution
    if (resourcesCreated.userId) {
      await cleanupScenarioRun({ userId: resourcesCreated.userId }).catch(() => {});
    }
    throw error;
  }
}

/**
 * Compares actual observed system outcome with expected interpretation for false-positive validation.
 *
 * @param {string} scenarioId
 * @param {object} [options={}]
 * @returns {Promise<object>} Comparison report
 */
async function compareFalsePositive(scenarioId, options = {}) {
  const scenario = getScenarioDefinition(scenarioId);
  if (!scenario) {
    throw new Error(`Unknown false-positive scenario: '${scenarioId}'`);
  }

  const runResult = await runScenario(scenarioId, options);
  const finalOutcome = runResult.final_outcome;
  const maxAcceptable =
    (scenario.expected_outcome && scenario.expected_outcome.max_acceptable_decision) || 'monitor';

  const order = ['allow', 'monitor', 'reverify', 'delay', 'block'];
  const actualRank = order.indexOf(finalOutcome.policy_decision);
  const maxRank = order.indexOf(maxAcceptable);
  const isAcceptable = actualRank <= maxRank && !finalOutcome.is_contained;

  return {
    scenario_id: scenario.id,
    scenario_name: scenario.name,
    expected_interpretation: scenario.expected_interpretation,
    expected_max_acceptable_decision: maxAcceptable,
    observed_system_outcome: {
      risk_score: finalOutcome.risk_score,
      risk_tier: finalOutcome.risk_tier,
      policy_decision: finalOutcome.policy_decision,
      enforcement_outcome: finalOutcome.enforcement_outcome,
      contributing_signals:
        runResult.steps[runResult.steps.length - 1]?.observed_pipeline.contributing_signals || [],
      is_contained: finalOutcome.is_contained
    },
    is_acceptable: isAcceptable,
    summary: runResult
  };
}

module.exports = {
  runScenario,
  compareFalsePositive
};
