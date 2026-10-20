'use strict';

const crypto = require('crypto');
const request = require('supertest');
const app = require('../src/app');
const { runMigrations } = require('../src/database/migrate');
const { User, SecurityEvent, PolicyDecision } = require('../src/database/models');
const { createAdminToken } = require('../src/services/adminTokenService');
const { cleanupScenarioRun } = require('../src/scenarios');

describe('Module 13.2 — Live Demo API End-to-End Integration', () => {
  let adminToken;

  beforeAll(async () => {
    await runMigrations();
    const adminTokRes = await createAdminToken();
    adminToken = adminTokRes.admin_token;
  });

  afterEach(async () => {
    jest.restoreAllMocks();
  });

  // Requirement 1 (E2E): Unauthorized requests without admin token are rejected with 401
  test('Requirement 1 (E2E): Unauthorized requests without admin token are rejected with 401', async () => {
    // 1. GET /demo/scenarios
    const getRes = await request(app).get('/api/v1/admin/demo/scenarios');
    expect(getRes.status).toBe(401);

    // 2. POST /demo/run
    const postRes = await request(app)
      .post('/api/v1/admin/demo/run')
      .send({ scenario_id: 'scenario_a' });
    expect(postRes.status).toBe(401);

    // 3. POST /demo/cleanup
    const cleanRes = await request(app)
      .post('/api/v1/admin/demo/cleanup')
      .send({ run_id: 'some_run' });
    expect(cleanRes.status).toBe(401);
  });

  // Requirement 2 (E2E): GET /api/v1/admin/demo/scenarios lists all available demo scenarios with metadata
  test('Requirement 2 (E2E): GET /api/v1/admin/demo/scenarios lists all available demo scenarios with metadata', async () => {
    const res = await request(app)
      .get('/api/v1/admin/demo/scenarios')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('scenarios');
    expect(Array.isArray(res.body.scenarios)).toBe(true);

    const ids = res.body.scenarios.map((s) => s.id);
    expect(ids).toContain('scenario_a');
    expect(ids).toContain('scenario_b');
    expect(ids).toContain('fp_benign_new_device');
    expect(ids).toContain('fp_benign_travel_login');
    expect(ids).toContain('fp_benign_profile_update');
  });

  // Requirement 3 (E2E): POST /api/v1/admin/demo/run executes Scenario A with real pipeline outcomes and zero containment
  test('Requirement 3 (E2E): POST /api/v1/admin/demo/run executes Scenario A with real pipeline outcomes and zero containment', async () => {
    const runId = `e2e_scen_a_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const res = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        scenario_id: 'scenario_a',
        run_id: runId,
        cleanup_after: false
      });

    try {
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.mode).toBe('scenario');

      const result = res.body.result;
      expect(result.scenario_id).toBe('scenario_a');
      expect(result.final_outcome.policy_decision).toBe('allow');
      expect(result.final_outcome.enforcement_outcome).toBe('allowed');
      expect(result.final_outcome.is_contained).toBe(false);

      // Verify records were actually persisted
      const user = await User.findByPk(result.user_id);
      expect(user).not.toBeNull();
      expect(user.locked_until).toBeNull();
    } finally {
      await cleanupScenarioRun({ runId });
    }
  });

  // Requirement 4 (E2E): POST /api/v1/admin/demo/run executes Scenario B with sequence detection and containment
  test('Requirement 4 (E2E): POST /api/v1/admin/demo/run executes Scenario B with sequence detection and containment', async () => {
    const runId = `e2e_scen_b_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const res = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        scenario_id: 'scenario_b',
        run_id: runId,
        cleanup_after: false
      });

    try {
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.mode).toBe('scenario');

      const result = res.body.result;
      expect(result.scenario_id).toBe('scenario_b');
      expect(result.final_outcome.risk_score).toBe(70);
      expect(result.final_outcome.policy_decision).toBe('block');
      expect(result.final_outcome.enforcement_outcome).toBe('contained_and_blocked');
      expect(result.final_outcome.is_contained).toBe(true);

      // Verify containment locked the account in the database
      const user = await User.findByPk(result.user_id);
      expect(user).not.toBeNull();
      expect(user.locked_until).not.toBeNull();
      expect(new Date(user.locked_until).getTime()).toBeGreaterThan(Date.now());
    } finally {
      await cleanupScenarioRun({ runId });
    }
  });

  // Requirement 5 (E2E): POST /api/v1/admin/demo/run handles false-positive fixtures with comparison report
  test('Requirement 5 (E2E): POST /api/v1/admin/demo/run handles false-positive fixtures with comparison report', async () => {
    const runId = `e2e_fp_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const res = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        scenario_id: 'fp_benign_new_device',
        run_id: runId,
        cleanup_after: true
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.mode).toBe('false_positive');

    const report = res.body.result;
    expect(report.scenario_id).toBe('fp_benign_new_device');
    expect(report.is_acceptable).toBe(true);
    expect(report.observed_system_outcome.policy_decision).toBe('allow');
    expect(report.observed_system_outcome.is_contained).toBe(false);
  });

  // Requirement 6 (E2E): POST /api/v1/admin/demo/cleanup safely purges only records owned by the demo run
  test('Requirement 6 (E2E): POST /api/v1/admin/demo/cleanup safely purges only records owned by the demo run', async () => {
    const runId = `e2e_clean_test_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

    // 1. Run scenario
    const runRes = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({
        scenario_id: 'scenario_a',
        run_id: runId,
        cleanup_after: false
      });
    expect(runRes.status).toBe(200);
    const userId = runRes.body.result.user_id;

    // Verify user exists in database
    expect(await User.findByPk(userId)).not.toBeNull();

    // 2. Call cleanup endpoint
    const cleanRes = await request(app)
      .post('/api/v1/admin/demo/cleanup')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ run_id: runId });

    expect(cleanRes.status).toBe(200);
    expect(cleanRes.body.success).toBe(true);
    expect(cleanRes.body.removed.users).toBe(1);

    // Verify user is removed
    expect(await User.findByPk(userId)).toBeNull();
  });

  // Requirement 7 (E2E): POST /api/v1/admin/demo/run rejects invalid or malformed scenario identifiers
  test('Requirement 7 (E2E): POST /api/v1/admin/demo/run rejects invalid or malformed scenario identifiers with 400 or 404', async () => {
    // Missing scenario_id
    const missingRes = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({});
    expect(missingRes.status).toBe(400);

    // Unknown scenario_id
    const unknownRes = await request(app)
      .post('/api/v1/admin/demo/run')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ scenario_id: 'non_existent_scenario_123' });
    expect(unknownRes.status).toBe(404);
  });

  // Requirement 8 (E2E): POST /api/v1/admin/demo/cleanup fails safely with 400 when both run_id and user_id are missing
  test('Requirement 8 (E2E): POST /api/v1/admin/demo/cleanup fails safely with 400 when both run_id and user_id are missing', async () => {
    const res = await request(app)
      .post('/api/v1/admin/demo/cleanup')
      .set('Authorization', `Bearer ${adminToken}`)
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });
});
