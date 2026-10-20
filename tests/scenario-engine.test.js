'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const {
  runScenario,
  compareFalsePositive,
  cleanupScenarioRun,
  SCENARIOS,
  getScenarioDefinition,
  listScenarioDefinitions,
  validateScenarioDefinition
} = require('../src/scenarios');
const policyLoader = require('../src/services/policyLoader');

describe('Module 13.1 — Scenario Engine & Deterministic Demo Fixtures', () => {
  beforeAll(async () => {
    await runMigrations();
  });

  afterEach(async () => {
    jest.restoreAllMocks();
  });

  // Requirement 1: Scenario definitions are valid and deterministic
  test('Requirement 1: Scenario definitions are valid, complete, and deterministic', () => {
    const scenarios = listScenarioDefinitions();
    expect(scenarios.length).toBeGreaterThanOrEqual(5);

    for (const sc of scenarios) {
      expect(typeof sc.id).toBe('string');
      expect(typeof sc.name).toBe('string');
      expect(typeof sc.description).toBe('string');
      expect(['benign', 'simulated_takeover', 'false_positive']).toContain(sc.scenario_type);
      expect(Array.isArray(sc.steps)).toBe(true);
      expect(sc.steps.length).toBeGreaterThan(0);
      expect(validateScenarioDefinition(sc)).toBe(true);
    }

    // Verify lookup by id and alias
    expect(getScenarioDefinition('scenario_a')).toBeDefined();
    expect(getScenarioDefinition('scenario_a_normal_user')).toBeDefined();
    expect(getScenarioDefinition('scenario_b')).toBeDefined();
    expect(getScenarioDefinition('scenario_b_simulated_takeover')).toBeDefined();
    expect(getScenarioDefinition('fp_benign_new_device')).toBeDefined();
  });

  // Requirement 2: Scenario A produces the intended event sequence through the supported application path
  test('Requirement 2: Scenario A produces the intended normal event sequence through the supported application path', async () => {
    const runId = `req2_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_a', {
      runId,
      cleanupAfter: false
    });

    try {
      expect(summary.scenario_id).toBe('scenario_a');
      expect(summary.scenario_type).toBe('benign');
      expect(summary.steps_executed).toBe(3);

      // Verify each step evaluated through the pipeline
      expect(summary.steps[0].event_type).toBe('login_success');
      expect(summary.steps[0].observed_pipeline.policy_decision).toBe('allow');
      expect(summary.steps[0].observed_pipeline.risk_tier).toBe('low');

      expect(summary.steps[1].event_type).toBe('phone_number_change');
      expect(summary.steps[1].observed_pipeline.policy_decision).toBe('allow');
      expect(summary.steps[1].observed_pipeline.risk_tier).toBe('low');

      expect(summary.steps[2].event_type).toBe('login_success');
      expect(summary.steps[2].observed_pipeline.policy_decision).toBe('allow');

      // Final outcome must be allow and uncontained
      expect(summary.final_outcome.policy_decision).toBe('allow');
      expect(summary.final_outcome.enforcement_outcome).toBe('allowed');
      expect(summary.final_outcome.is_contained).toBe(false);
    } finally {
      await cleanupScenarioRun(summary);
    }
  });

  // Requirement 3: Scenario B generates supported suspicious signals without real attack traffic
  test('Requirement 3: Scenario B generates supported suspicious signals without real attack traffic', async () => {
    const runId = `req3_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_b', {
      runId,
      cleanupAfter: false
    });

    try {
      expect(summary.scenario_id).toBe('scenario_b');
      expect(summary.scenario_type).toBe('simulated_takeover');
      expect(summary.steps_executed).toBe(3);

      // Step 1: Initial attacker login has novelty signals
      const step1Signals = summary.steps[0].observed_pipeline.contributing_signals.map((s) => s.signal);
      expect(step1Signals).toContain('unrecognized_device');
      expect(step1Signals).toContain('unrecognized_country');

      // Step 2: Account modification escalates to reverify
      expect(summary.steps[1].event_type).toBe('recovery_email_change');
      expect(summary.steps[1].observed_pipeline.policy_decision).toBe('reverify');

      // Step 3: High impact action triggers seq_takeover_progression and block
      const step3Signals = summary.steps[2].observed_pipeline.contributing_signals.map((s) => s.signal);
      expect(step3Signals).toContain('seq_takeover_progression');
      expect(summary.steps[2].observed_pipeline.policy_decision).toBe('block');

      // Final outcome is blocked and contained
      expect(summary.final_outcome.policy_decision).toBe('block');
      expect(summary.final_outcome.enforcement_outcome).toBe('contained_and_blocked');
      expect(summary.final_outcome.is_contained).toBe(true);

      // Verify user account was locked in database
      const user = await User.findByPk(summary.user_id);
      expect(user).not.toBeNull();
      expect(user.locked_until).not.toBeNull();
      expect(new Date(user.locked_until).getTime()).toBeGreaterThan(Date.now());
    } finally {
      await cleanupScenarioRun(summary);
    }
  });

  // Requirement 4: Events are actually passed through the existing evaluation pipeline
  test('Requirement 4: Events are actually passed through the existing evaluation pipeline and persisted', async () => {
    const runId = `req4_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_a', {
      runId,
      cleanupAfter: false
    });

    try {
      // 1. Verify SecurityEvents in MySQL
      const eventsInDb = await SecurityEvent.findAll({
        where: { user_id: summary.user_id }
      });
      // 1 baseline event + 3 steps = 4 events
      expect(eventsInDb.length).toBe(4);

      // 2. Verify RiskAssessments in MySQL
      const assessmentsInDb = await RiskAssessment.findAll({
        where: { user_id: summary.user_id }
      });
      expect(assessmentsInDb.length).toBeGreaterThanOrEqual(3);

      // 3. Verify PolicyDecisions in MySQL
      const decisionsInDb = await PolicyDecision.findAll({
        where: { user_id: summary.user_id }
      });
      expect(decisionsInDb.length).toBe(3);

      // 4. Verify ActionSequence in MySQL
      const sequencesInDb = await ActionSequence.findAll({
        where: { user_id: summary.user_id }
      });
      expect(sequencesInDb.length).toBeGreaterThanOrEqual(1);
    } finally {
      await cleanupScenarioRun(summary);
    }
  });

  // Requirement 5: The runner reports the real observed decisions rather than predetermined results
  test('Requirement 5: The runner reports the real observed decisions and scores rather than predetermined results', async () => {
    const runId = `req5_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_b', {
      runId,
      cleanupAfter: false
    });

    try {
      const lastStep = summary.steps[summary.steps.length - 1];
      const eventId = lastStep.observed_pipeline.event_id;

      // Fetch the actual record directly from MySQL
      const dbDecision = await PolicyDecision.findOne({
        where: { event_id: eventId }
      });
      const dbAssessment = await RiskAssessment.findOne({
        where: { event_id: eventId }
      });

      expect(dbDecision).not.toBeNull();
      expect(dbAssessment).not.toBeNull();

      // The runner's reported output must match the database truth exactly
      expect(lastStep.observed_pipeline.risk_score).toBe(dbAssessment.risk_score);
      expect(lastStep.observed_pipeline.risk_tier).toBe(dbAssessment.risk_tier);
      expect(lastStep.observed_pipeline.policy_decision).toBe(dbDecision.effective_decision);
      expect(lastStep.observed_pipeline.enforcement_outcome).toBe(dbDecision.enforcement_outcome);
    } finally {
      await cleanupScenarioRun(summary);
    }
  });

  // Requirement 6: False-positive fixtures preserve legitimate context and expose the actual system outcome
  test('Requirement 6: False-positive fixtures preserve legitimate context and expose the actual system outcome', async () => {
    // Check 1: Benign new device
    const fpDevReport = await compareFalsePositive('fp_benign_new_device', {
      cleanupAfter: true
    });
    expect(fpDevReport.is_acceptable).toBe(true);
    expect(fpDevReport.observed_system_outcome.policy_decision).toBe('allow');
    expect(fpDevReport.observed_system_outcome.is_contained).toBe(false);
    expect(
      fpDevReport.observed_system_outcome.contributing_signals.some(
        (s) => s.signal === 'unrecognized_device'
      )
    ).toBe(true);

    // Check 2: Feasible travel login
    const fpTravelReport = await compareFalsePositive('fp_benign_travel_login', {
      cleanupAfter: true
    });
    expect(fpTravelReport.is_acceptable).toBe(true);
    expect(fpTravelReport.observed_system_outcome.policy_decision).toBe('allow');
    expect(fpTravelReport.observed_system_outcome.is_contained).toBe(false);
    expect(
      fpTravelReport.observed_system_outcome.contributing_signals.some(
        (s) => s.signal === 'unrecognized_country'
      )
    ).toBe(true);

    // Check 3: Routine profile update
    const fpProfileReport = await compareFalsePositive('fp_benign_profile_update', {
      cleanupAfter: true
    });
    expect(fpProfileReport.is_acceptable).toBe(true);
    expect(fpProfileReport.observed_system_outcome.policy_decision).toBe('allow');
    expect(fpProfileReport.observed_system_outcome.is_contained).toBe(false);
  });

  // Requirement 7: Rerunning a scenario does not cause uncontrolled duplicate data
  test('Requirement 7: Rerunning a scenario with the same run identifier cleans up or prevents uncontrolled duplicate data', async () => {
    const sharedRunId = `shared_run_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

    // First execution
    const firstRun = await runScenario('scenario_a', {
      runId: sharedRunId,
      cleanupBefore: true,
      cleanupAfter: false
    });

    const firstEventsCount = await SecurityEvent.count({
      where: { user_id: firstRun.user_id }
    });
    expect(firstEventsCount).toBe(4);

    // Second execution with SAME runId
    const secondRun = await runScenario('scenario_a', {
      runId: sharedRunId,
      cleanupBefore: true,
      cleanupAfter: false
    });

    const secondEventsCount = await SecurityEvent.count({
      where: { user_id: secondRun.user_id }
    });
    // Count should be exactly 4, NOT 8 (prior run data was safely replaced)
    expect(secondEventsCount).toBe(4);

    await cleanupScenarioRun(secondRun);
  });

  // Requirement 8: Cleanup removes only records owned by that scenario run
  test('Requirement 8: Cleanup removes only records owned by that scenario run and preserves unrelated user data', async () => {
    // 1. Seed an unrelated user record
    const unrelatedEmail = `unrelated-${Date.now()}@actionguard.test`;
    const passwordHash = await bcrypt.hash('CorrectHorseStaple99!', 10);
    const unrelatedUser = await User.create({
      email: unrelatedEmail,
      password_hash: passwordHash
    });

    const unrelatedEvent = await SecurityEvent.create({
      user_id: unrelatedUser.id,
      event_type: 'login_success',
      timestamp: new Date()
    });

    // 2. Run a scenario
    const runId = `req8_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_a', {
      runId,
      cleanupAfter: false
    });

    // 3. Clean up the scenario run
    const cleanupResult = await cleanupScenarioRun(summary);
    expect(cleanupResult.success).toBe(true);
    expect(cleanupResult.removed.users).toBe(1);

    // 4. Verify scenario records are gone
    const scenarioUser = await User.findByPk(summary.user_id);
    expect(scenarioUser).toBeNull();

    // 5. Verify UNRELATED records remain intact!
    const preservedUser = await User.findByPk(unrelatedUser.id);
    expect(preservedUser).not.toBeNull();
    expect(preservedUser.email).toBe(unrelatedEmail);

    const preservedEvent = await SecurityEvent.findByPk(unrelatedEvent.event_id);
    expect(preservedEvent).not.toBeNull();

    // Teardown the unrelated test record
    await SecurityEvent.destroy({ where: { user_id: unrelatedUser.id }, force: true });
    await User.destroy({ where: { id: unrelatedUser.id }, force: true });
  });

  // Requirement 9: Repeated cleanup is safe
  test('Requirement 9: Repeated cleanup is idempotent and safe without throwing errors', async () => {
    const runId = `req9_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_a', {
      runId,
      cleanupAfter: false
    });

    // First cleanup
    const res1 = await cleanupScenarioRun(summary);
    expect(res1.success).toBe(true);
    expect(res1.removed.users).toBe(1);

    // Second cleanup of same run context
    const res2 = await cleanupScenarioRun(summary);
    expect(res2.success).toBe(true);
    expect(res2.removed.users).toBe(0);

    // Third cleanup with runId string only
    const res3 = await cleanupScenarioRun({ runId });
    expect(res3.success).toBe(true);
    expect(res3.removed.users).toBe(0);
  });

  // Requirement 10: Invalid scenario names and malformed parameters fail safely
  test('Requirement 10: Invalid scenario names and malformed parameters fail safely with descriptive errors', async () => {
    // 1. Unknown scenario ID
    await expect(runScenario('invalid_scenario_id_999')).rejects.toThrow(
      /unknown scenario identifier/i
    );

    // 2. Empty scenario ID
    await expect(runScenario('')).rejects.toThrow(
      /unknown scenario identifier/i
    );

    // 3. Malformed cleanup parameters (missing both userId and runId)
    await expect(cleanupScenarioRun({})).rejects.toThrow(
      /either userId or runId must be provided/i
    );

    await expect(cleanupScenarioRun(null)).rejects.toThrow(
      /must be a non-null object/i
    );

    // 4. Invalid definition validator
    expect(() => validateScenarioDefinition(null)).toThrow(/must be a non-null object/i);
    expect(() => validateScenarioDefinition({ id: 'bad', scenario_type: 'unknown' })).toThrow(
      /invalid scenario_type/i
    );
    expect(() =>
      validateScenarioDefinition({
        id: 'bad_events',
        scenario_type: 'benign',
        steps: [{ event_type: 'unsupported_custom_action', time_offset_ms: 0 }]
      })
    ).toThrow(/unsupported event_type/i);
  });

  // Requirement 11: Tests do not touch development or production data
  test('Requirement 11: Tests operate on isolated run-scoped identifiers and do not touch development or production data', async () => {
    const runId = `req11_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const summary = await runScenario('scenario_a', {
      runId,
      cleanupAfter: false
    });

    try {
      // Must use dedicated demo domain
      expect(summary.user_email).toMatch(/^demo-scenario_a-req11_/);
      expect(summary.user_email).toMatch(/@demo\.actionguard\.local$/);

      // Must never target or match dev seed user
      expect(summary.user_email).not.toBe('dev-seed-user@actionguard.test');
      expect(summary.user_id).not.toBe('usr_dev_seed_0001');
    } finally {
      await cleanupScenarioRun(summary);
    }
  });

  // Requirement 12: Existing tests and security behavior remain intact
  test('Requirement 12: Existing security behavior and policy evaluations remain intact and unweakened', () => {
    const activePolicy = policyLoader.getActivePolicy();
    expect(activePolicy).toBeDefined();
    expect(activePolicy.policy_id).toBe('default-v1');

    // Verify critical policy invariants were not altered
    expect(activePolicy.DEFAULT_ACTION_SENSITIVITY.high_impact_action).toBe('critical');
    expect(activePolicy.DEFAULT_ACTION_SENSITIVITY.password_change).toBe('high');
    expect(activePolicy.BASE_MATRIX.critical.critical).toBe('block');
    expect(activePolicy.BASE_MATRIX.high.critical).toBe('block');
  });
});
