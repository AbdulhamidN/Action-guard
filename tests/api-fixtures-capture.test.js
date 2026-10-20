/**
 * @fileoverview Integration test suite for Admin API fixture capture and validation.
 * Verifies that real HTTP responses generated from the running test application
 * contain the exact data models and graph relationships required for Module 12c-1.
 */

const fs = require('fs');
const path = require('path');
const {
  captureApiExamples,
  normalizeFixture,
  findDifferences,
  DEMO_USER_ID,
  TEST_ADMIN_KEY
} = require('../scripts/generate-api-examples');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const { getRedisClient } = require('../src/storage/redis');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

const FIXTURES_DIR = path.resolve(__dirname, '../docs/api-examples');

describe('Module 12c-1 Prerequisite — Admin API Fixture Capture & Validation', () => {
  let captured;
  let origAdminKey;

  beforeAll(async () => {
    origAdminKey = process.env.ACTIONGUARD_ADMIN_API_KEY;
    process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY;

    captured = await captureApiExamples({ outputDir: FIXTURES_DIR, writeToDisk: false });
  });

  afterAll(async () => {
    process.env.ACTIONGUARD_ADMIN_API_KEY = origAdminKey;

    // Clean up database tables
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await PolicyDecision.destroy({ where: {}, force: true });
    await RiskAssessment.destroy({ where: {}, force: true });
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    // Clean up Redis admin tokens
    const redis = getRedisClient();
    if (typeof redis.keys === 'function') {
      const keys = await redis.keys(`${REDIS_PREFIXES.ADMIN_TOKEN}*`);
      if (keys.length > 0) {
        await redis.del(...keys);
      }
    } else if (redis.store && typeof redis.store.clear === 'function') {
      redis.store.clear();
    }
  });

  test('captures GET /api/v1/admin/overview?window=24h with aggregated outcome and tier metrics', () => {
    const data = captured['admin-overview-24h'];
    expect(data).toBeDefined();
    expect(data.window).toBe('24h');
    expect(typeof data.window_start).toBe('string');
    expect(typeof data.window_end).toBe('string');
    expect(new Date(data.window_start).getTime()).toBeLessThan(new Date(data.window_end).getTime());

    // Decisions by outcome breakdown
    expect(data.decisions_by_outcome).toBeDefined();
    expect(typeof data.decisions_by_outcome.allow).toBe('number');
    expect(typeof data.decisions_by_outcome.monitor).toBe('number');
    expect(typeof data.decisions_by_outcome.reverify).toBe('number');
    expect(typeof data.decisions_by_outcome.delay).toBe('number');
    expect(typeof data.decisions_by_outcome.block).toBe('number');
    expect(typeof data.decisions_by_outcome.contained_and_blocked).toBe('number');

    // Assessments by tier breakdown
    expect(data.assessments_by_tier).toBeDefined();
    expect(typeof data.assessments_by_tier.low).toBe('number');
    expect(typeof data.assessments_by_tier.medium).toBe('number');
    expect(typeof data.assessments_by_tier.high).toBe('number');
    expect(typeof data.assessments_by_tier.critical).toBe('number');

    expect(typeof data.active_sessions).toBe('number');
    expect(typeof data.contained_sessions).toBe('number');
  });

  test('captures GET /api/v1/admin/overview?window=7d with 7-day aggregates', () => {
    const data = captured['admin-overview-7d'];
    expect(data).toBeDefined();
    expect(data.window).toBe('7d');
    expect(typeof data.window_start).toBe('string');
    expect(typeof data.window_end).toBe('string');
    expect(new Date(data.window_start).getTime()).toBeLessThan(new Date(data.window_end).getTime());
    expect(data.decisions_by_outcome).toBeDefined();
    expect(data.assessments_by_tier).toBeDefined();
  });

  test('captures GET /api/v1/admin/users with pagination, active session counts, and latest risk tiers', () => {
    const data = captured['admin-users'];
    expect(data).toBeDefined();
    expect(Array.isArray(data.users)).toBe(true);
    expect(typeof data.total).toBe('number');
    expect(data.users.length).toBeGreaterThanOrEqual(2);

    const demoUser = data.users.find((u) => u.id === DEMO_USER_ID);
    expect(demoUser).toBeDefined();
    expect(demoUser.email).toBe('alex.security@actionguard.test');
    expect(typeof demoUser.created_at).toBe('string');
    expect(demoUser.latest_risk_tier).toBe('critical');
    expect(typeof demoUser.latest_risk_at).toBe('string');
    expect(demoUser.active_sessions).toBeGreaterThanOrEqual(1);
  });

  test('captures GET /api/v1/admin/users/:id/events with event types, device_ref, and location', () => {
    const data = captured['admin-user-events'];
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(4);

    const pwdEvent = data.find((e) => e.event_type === 'password_change');
    expect(pwdEvent).toBeDefined();
    expect(pwdEvent.user_id).toBe(DEMO_USER_ID);
    expect(typeof pwdEvent.timestamp).toBe('string');
    expect(typeof pwdEvent.device_ref).toBe('string');
    expect(pwdEvent.device_ref.length).toBe(12);
    expect(pwdEvent.coarse_location).toEqual({ country: 'RU', region: 'MOW' });
  });

  test('captures GET /api/v1/admin/users/:id/risk-history with numeric score, tier, contributing signals, and dual explanations', () => {
    const data = captured['admin-user-risk-history'];
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(2);

    const critAssessment = data.find((a) => a.risk_tier === 'critical');
    expect(critAssessment).toBeDefined();
    expect(critAssessment.user_id).toBe(DEMO_USER_ID);
    expect(critAssessment.risk_score).toBe(88);
    expect(Array.isArray(critAssessment.contributing_signals)).toBe(true);
    expect(critAssessment.contributing_signals.length).toBeGreaterThanOrEqual(3);

    for (const sig of critAssessment.contributing_signals) {
      expect(typeof sig.signal).toBe('string');
      expect(typeof sig.category).toBe('string');
      expect(typeof sig.weight).toBe('number');
    }

    expect(critAssessment.explanation).toBeDefined();
    expect(typeof critAssessment.explanation.user_facing).toBe('string');
    expect(typeof critAssessment.explanation.admin_facing).toBe('string');
    expect(critAssessment.explanation.user_facing.length).toBeGreaterThan(0);
    expect(critAssessment.explanation.admin_facing.length).toBeGreaterThan(0);
  });

  test('captures GET /api/v1/admin/users/:id/decisions with policy reasons, decision outcomes, and graph linkage', () => {
    const data = captured['admin-user-decisions'];
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(2);

    const critDecision = data.find((d) => d.effective_decision === 'block');
    expect(critDecision).toBeDefined();
    expect(critDecision.user_id).toBe(DEMO_USER_ID);
    expect(critDecision.action_type).toBe('password_change');
    expect(critDecision.action_sensitivity).toBe('critical');
    expect(critDecision.risk_tier).toBe('critical');
    expect(critDecision.enforcement_outcome).toBe('contained_and_blocked');
    expect(critDecision.policy_version).toBe('default-v1@1.0.0');

    expect(Array.isArray(critDecision.reasons)).toBe(true);
    expect(critDecision.reasons.length).toBeGreaterThanOrEqual(1);
    for (const r of critDecision.reasons) {
      expect(typeof r.source).toBe('string');
      expect(typeof r.rule_id).toBe('string');
      expect(typeof r.decision).toBe('string');
    }

    expect(Array.isArray(critDecision.contributing_signals)).toBe(true);
    expect(critDecision.explanation).toBeDefined();
    expect(typeof critDecision.explanation.user_facing).toBe('string');
    expect(typeof critDecision.explanation.admin_facing).toBe('string');
  });

  test('captures GET /api/v1/admin/users/:id/sessions with risk tier, score, and coarse location', () => {
    const data = captured['admin-user-sessions'];
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThanOrEqual(2);

    const activeSession = data.find((s) => s.is_active === true);
    expect(activeSession).toBeDefined();
    expect(activeSession.user_id).toBe(DEMO_USER_ID);
    expect(typeof activeSession.created_at).toBe('string');
    expect(typeof activeSession.expires_at).toBe('string');
    expect(activeSession.risk_tier).toBe('low');
    expect(activeSession.risk_score).toBe(15);
  });

  test('captures GET /api/v1/admin/users/:id/sequence with ordered multi-step events and sensitivities', () => {
    const data = captured['admin-user-sequence'];
    expect(data).toBeDefined();
    expect(data.sequence).not.toBeNull();
    expect(data.sequence.user_id).toBe(DEMO_USER_ID);
    expect(typeof data.sequence.started_at).toBe('string');
    expect(typeof data.sequence.last_event_at).toBe('string');
    expect(data.sequence.event_count).toBe(2);

    expect(Array.isArray(data.sequence.events)).toBe(true);
    expect(data.sequence.events.length).toBe(2);
    expect(data.sequence.events[0].step_order).toBe(1);
    expect(data.sequence.events[1].step_order).toBe(2);
    expect(data.sequence.events[1].action_sensitivity).toBe('critical');
  });

  test('captures GET /api/v1/admin/policy with active schema, matrix, and escalation rules', () => {
    const data = captured['admin-policy'];
    expect(data).toBeDefined();
    expect(data.policy_id).toBe('default-v1');
    expect(data.schema_version).toBe('1.0.0');
    expect(typeof data.description).toBe('string');
    expect(data.BASE_MATRIX).toBeDefined();
    expect(Array.isArray(data.ESCALATION_RULES)).toBe(true);
    expect(data.DEFAULT_ACTION_SENSITIVITY).toBeDefined();
    expect(Array.isArray(data.DECISION_ORDER)).toBe(true);
  });

  test('verifies explanation graph entity relationships are consistent across captured fixtures', () => {
    const decisions = captured['admin-user-decisions'];
    const riskHistory = captured['admin-user-risk-history'];
    const events = captured['admin-user-events'];
    const sequence = captured['admin-user-sequence'];

    const criticalDecision = decisions.find((d) => d.effective_decision === 'block');
    const criticalAssessment = riskHistory.find((a) => a.risk_tier === 'critical');
    const pwdEvent = events.find((e) => e.event_type === 'password_change');

    // 1. Decision links to Risk Assessment via risk_assessment_id
    expect(criticalDecision.risk_assessment_id).toBe(criticalAssessment.id);

    // 2. Decision and Assessment link to Security Event via event_id
    expect(criticalDecision.event_id).toBe(pwdEvent.event_id);
    expect(criticalAssessment.event_id).toBe(pwdEvent.event_id);

    // 3. Sequence events contain the triggering Security Event
    const seqEventIds = sequence.sequence.events.map((e) => e.event_id);
    expect(seqEventIds).toContain(pwdEvent.event_id);

    // 4. Contributing signals match between Assessment and Decision
    expect(criticalDecision.contributing_signals).toEqual(criticalAssessment.contributing_signals);
  });

  test('verifies all generated fixtures exist and contain valid JSON', () => {
    const expectedFiles = [
      'admin-overview-24h.json',
      'overview-24h.json',
      'admin-overview-7d.json',
      'overview-7d.json',
      'admin-users.json',
      'users.json',
      'admin-user-events.json',
      'user-events.json',
      'admin-user-risk-history.json',
      'user-risk-history.json',
      'admin-user-decisions.json',
      'user-decisions.json',
      'admin-user-sessions.json',
      'user-sessions.json',
      'admin-user-sequence.json',
      'user-sequence.json',
      'admin-policy.json',
      'policy.json',
      'README.md'
    ];

    for (const file of expectedFiles) {
      const filePath = path.join(FIXTURES_DIR, file);
      expect(fs.existsSync(filePath)).toBe(true);

      if (file.endsWith('.json')) {
        const content = fs.readFileSync(filePath, 'utf-8');
        expect(() => JSON.parse(content)).not.toThrow();
        const parsed = JSON.parse(content);
        expect(parsed).not.toBeNull();
      }
    }
  });

  test('verifies zero secrets, bearer tokens, passwords, or raw keys in all generated fixtures', () => {
    const fixtureFiles = fs.readdirSync(FIXTURES_DIR).filter((f) => f.endsWith('.json'));
    expect(fixtureFiles.length).toBeGreaterThanOrEqual(9);

    const sensitiveKeyPattern = /^(secret|apiKey|authorization|bearer|password|password_hash)$/i;
    const tokenPattern = /^agadm_[a-zA-Z0-9_-]{16,}|^eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\./;
    const privateKeyPattern = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
    const ipAddressPattern = /^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$/;
    const bcryptPattern = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

    const violations = [];

    function scanNode(node, currentPath, fileName) {
      if (node === null || node === undefined) return;
      if (Array.isArray(node)) {
        node.forEach((item, idx) => scanNode(item, `${currentPath}[${idx}]`, fileName));
        return;
      }
      if (typeof node === 'object') {
        for (const [key, val] of Object.entries(node)) {
          if (sensitiveKeyPattern.test(key)) {
            violations.push({ file: fileName, path: `${currentPath}.${key}`, category: 'sensitive_property_name' });
          }
          scanNode(val, `${currentPath}.${key}`, fileName);
        }
        return;
      }
      if (typeof node === 'string') {
        if (tokenPattern.test(node)) {
          violations.push({ file: fileName, path: currentPath, category: 'bearer_or_session_token' });
        }
        if (privateKeyPattern.test(node)) {
          violations.push({ file: fileName, path: currentPath, category: 'private_key_block' });
        }
        if (ipAddressPattern.test(node)) {
          violations.push({ file: fileName, path: currentPath, category: 'raw_ipv4_address' });
        }
        if (bcryptPattern.test(node)) {
          violations.push({ file: fileName, path: currentPath, category: 'bcrypt_password_hash' });
        }
      }
    }

    for (const file of fixtureFiles) {
      const content = fs.readFileSync(path.join(FIXTURES_DIR, file), 'utf-8');

      // 1. Literal substring checks against known test constants
      expect(content).not.toContain(TEST_ADMIN_KEY);
      expect(content).not.toContain('Password123!');
      expect(content).not.toContain('password_hash');
      expect(content).not.toContain('$2b$');
      expect(content).not.toContain('agadm_');
      expect(content).not.toContain('198.51.100.10');
      expect(content).not.toContain('203.0.113.88');
      expect(content).not.toContain('fp_fixture_desktop_chrome_01');
      expect(content).not.toContain('fp_fixture_unrecognized_device_99');

      // 2. Recursive structural & regex pattern scan
      const parsed = JSON.parse(content);
      scanNode(parsed, '$', file);
    }

    if (violations.length > 0) {
      const summary = violations.map((v) => `[${v.category}] in ${v.file} at ${v.path}`).join('; ');
      throw new Error(`Security scan failed with ${violations.length} violations: ${summary}`);
    }

    expect(violations).toHaveLength(0);
  });

  test('verifies live API responses match committed fixture baselines (drift protection)', () => {
    const fixtureKeys = [
      'admin-overview-24h',
      'admin-overview-7d',
      'admin-users',
      'admin-user-events',
      'admin-user-risk-history',
      'admin-user-decisions',
      'admin-user-sessions',
      'admin-user-sequence',
      'admin-policy'
    ];

    const allDiffs = [];

    for (const key of fixtureKeys) {
      const live = captured[key];
      expect(live).toBeDefined();

      const committedPath = path.join(FIXTURES_DIR, `${key}.json`);
      expect(fs.existsSync(committedPath)).toBe(true);

      const committedRaw = fs.readFileSync(committedPath, 'utf-8');
      const committed = JSON.parse(committedRaw);

      const normalizedLive = normalizeFixture(live);
      const normalizedCommitted = normalizeFixture(committed);

      const diffs = findDifferences(normalizedLive, normalizedCommitted, `$`);
      if (diffs.length > 0) {
        allDiffs.push(`[Drift in ${key}.json]: ${diffs.join('; ')}`);
      }
    }

    if (allDiffs.length > 0) {
      throw new Error(`API fixture drift detected across ${allDiffs.length} files:\n${allDiffs.join('\n')}`);
    }

    expect(allDiffs).toHaveLength(0);
  });

  test('confirms normal test execution does not modify fixture file timestamps or contents', async () => {
    const fixtureFiles = fs.readdirSync(FIXTURES_DIR).filter((f) => f.endsWith('.json'));

    const beforeStats = fixtureFiles.map((file) => {
      const filePath = path.join(FIXTURES_DIR, file);
      const stat = fs.statSync(filePath);
      const content = fs.readFileSync(filePath, 'utf-8');
      return { file, mtimeMs: stat.mtimeMs, size: stat.size, content };
    });

    // Run another in-memory capture without writeToDisk
    await captureApiExamples({ outputDir: FIXTURES_DIR, writeToDisk: false });

    for (const before of beforeStats) {
      const filePath = path.join(FIXTURES_DIR, before.file);
      const stat = fs.statSync(filePath);
      const content = fs.readFileSync(filePath, 'utf-8');

      expect(stat.mtimeMs).toBe(before.mtimeMs);
      expect(stat.size).toBe(before.size);
      expect(content).toBe(before.content);
    }
  });

  test('drift protection detects and reports contract divergence when expected baseline changes', () => {
    // 1. Simulating modified property value
    const modifiedUsers = JSON.parse(JSON.stringify(captured['admin-users']));
    modifiedUsers.total = 999;
    const diff1 = findDifferences(normalizeFixture(modifiedUsers), normalizeFixture(captured['admin-users']));
    expect(diff1.length).toBeGreaterThan(0);
    expect(diff1[0]).toContain('Value mismatch at $.total: expected 3, received 999');

    // 2. Simulating missing property in live response
    const missingProp = JSON.parse(JSON.stringify(captured['admin-policy']));
    delete missingProp.BASE_MATRIX;
    const diff2 = findDifferences(normalizeFixture(missingProp), normalizeFixture(captured['admin-policy']));
    expect(diff2.length).toBeGreaterThan(0);
    expect(diff2.some((d) => d.includes('Missing properties at $: [BASE_MATRIX]'))).toBe(true);

    // 3. Simulating unexpected type divergence
    const typeDivergence = JSON.parse(JSON.stringify(captured['admin-overview-24h']));
    typeDivergence.active_sessions = 'two';
    const diff3 = findDifferences(normalizeFixture(typeDivergence), normalizeFixture(captured['admin-overview-24h']));
    expect(diff3.length).toBeGreaterThan(0);
    expect(diff3.some((d) => d.includes('Type mismatch at $.active_sessions: expected number, received string'))).toBe(true);
  });

  test('supports explicit regeneration only when REGENERATE_FIXTURES=true is set', async () => {
    // Verify default behavior in test is writeToDisk: false
    const origEnv = process.env.REGENERATE_FIXTURES;
    delete process.env.REGENERATE_FIXTURES;

    const tmpOutputDir = path.join(__dirname, '../scratch/test-regenerate-optin');
    try {
      if (fs.existsSync(tmpOutputDir)) {
        fs.rmSync(tmpOutputDir, { recursive: true, force: true });
      }

      // Default run in test: does not write to disk
      await captureApiExamples({ outputDir: tmpOutputDir });
      expect(fs.existsSync(tmpOutputDir)).toBe(false);

      // Explicit opt-in with REGENERATE_FIXTURES=true writes to disk
      process.env.REGENERATE_FIXTURES = 'true';
      await captureApiExamples({ outputDir: tmpOutputDir });
      expect(fs.existsSync(tmpOutputDir)).toBe(true);
      expect(fs.existsSync(path.join(tmpOutputDir, 'admin-overview-24h.json'))).toBe(true);
      expect(fs.existsSync(path.join(tmpOutputDir, 'README.md'))).toBe(true);
    } finally {
      if (origEnv !== undefined) {
        process.env.REGENERATE_FIXTURES = origEnv;
      } else {
        delete process.env.REGENERATE_FIXTURES;
      }
      if (fs.existsSync(tmpOutputDir)) {
        fs.rmSync(tmpOutputDir, { recursive: true, force: true });
      }
    }
  });
});
