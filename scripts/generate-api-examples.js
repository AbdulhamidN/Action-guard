/**
 * @fileoverview Captures real HTTP JSON response fixtures from ActionGuard API.
 * Uses test database and test Redis in the test environment.
 * Generates docs/api-examples/*.json with provenance documentation.
 */

const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const request = require('supertest');

const app = require('../src/app');
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
const { runMigrations } = require('../src/database/migrate');
const { getRedisClient } = require('../src/storage/redis');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

const TEST_ADMIN_KEY = 'admin_secret_key_with_at_least_32_characters_12345';
const TEST_PASSWORD = 'Password123!';

const DEMO_USER_ID = 'usr_fixture_admin_demo_01';
const USER_2_ID = 'usr_fixture_standard_02';
const USER_3_ID = 'usr_fixture_contained_03';

const SESSION_1_ID = 'sess_fixture_active_01';
const SESSION_2_ID = 'sess_fixture_contained_02';
const SESSION_3_ID = 'sess_fixture_user2_03';

const EVENT_1_ID = 'evt_fixture_01_login';
const EVENT_2_ID = 'evt_fixture_02_new_dev';
const EVENT_3_ID = 'evt_fixture_03_recovery';
const EVENT_4_ID = 'evt_fixture_04_pwd_change';
const EVENT_5_ID = 'evt_fixture_05_containment';

const SEQUENCE_ID = 'seq_fixture_takeover_01';

const ASSESSMENT_1_ID = 'ra_fixture_01_low';
const ASSESSMENT_2_ID = 'ra_fixture_02_critical';

const DECISION_1_ID = 'dec_fixture_01_allowed';
const DECISION_2_ID = 'dec_fixture_02_contained';

/**
 * Seeds deterministic security data for fixture generation.
 * Timestamps are computed relative to Date.now().
 *
 * @returns {Promise<void>}
 */
async function seedFixtureData() {
  await runMigrations();

  // Clean up any existing fixture records safely
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

  const nowMs = Date.now();
  const tMinus30m = new Date(nowMs - 30 * 60 * 1000);
  const tMinus20m = new Date(nowMs - 20 * 60 * 1000);
  const tMinus15m = new Date(nowMs - 15 * 60 * 1000);
  const tMinus10m = new Date(nowMs - 10 * 60 * 1000);
  const tMinus5m = new Date(nowMs - 5 * 60 * 1000);
  const tPlus24h = new Date(nowMs + 24 * 60 * 60 * 1000);
  const tMinus1h = new Date(nowMs - 60 * 60 * 1000);

  const passwordHash = await bcrypt.hash(TEST_PASSWORD, 10);

  // 1. Users
  const user1 = await User.create({
    id: DEMO_USER_ID,
    email: 'alex.security@actionguard.test',
    password_hash: passwordHash,
    created_at: tMinus30m
  });

  const user2 = await User.create({
    id: USER_2_ID,
    email: 'sam.operator@actionguard.test',
    password_hash: passwordHash,
    created_at: tMinus30m
  });

  const user3 = await User.create({
    id: USER_3_ID,
    email: 'contained.target@actionguard.test',
    password_hash: passwordHash,
    locked_until: new Date(nowMs + 15 * 60 * 1000),
    created_at: tMinus30m
  });

  // 2. Devices
  await Device.create({
    id: 'dev_fixture_desktop_01',
    user_id: user1.id,
    fingerprint: 'fp_fixture_desktop_chrome_01',
    is_trusted: true,
    first_seen_at: tMinus30m
  });

  // 3. Sessions
  await Session.create({
    id: SESSION_1_ID,
    user_id: user1.id,
    is_active: true,
    created_at: tMinus30m,
    expires_at: tPlus24h
  });

  await Session.create({
    id: SESSION_2_ID,
    user_id: user1.id,
    is_active: false,
    created_at: tMinus10m,
    expires_at: tMinus5m
  });

  await Session.create({
    id: SESSION_3_ID,
    user_id: user2.id,
    is_active: true,
    created_at: tMinus20m,
    expires_at: tPlus24h
  });

  // 4. Security Events for user 1
  await SecurityEvent.create({
    event_id: EVENT_1_ID,
    user_id: user1.id,
    session_id: SESSION_1_ID,
    event_type: 'login_success',
    timestamp: tMinus30m,
    ip_address: '198.51.100.10',
    context: {
      geo_country: 'US',
      geo_region: 'CA',
      device_fingerprint: 'fp_fixture_desktop_chrome_01'
    },
    metadata: { action_sensitivity: 'low' }
  });

  await SecurityEvent.create({
    event_id: EVENT_2_ID,
    user_id: user1.id,
    session_id: SESSION_1_ID,
    event_type: 'new_device',
    timestamp: tMinus20m,
    ip_address: '198.51.100.10',
    context: {
      geo_country: 'US',
      geo_region: 'CA',
      device_fingerprint: 'fp_fixture_desktop_chrome_01'
    },
    metadata: { action_sensitivity: 'low' }
  });

  await SecurityEvent.create({
    event_id: EVENT_3_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    event_type: 'recovery_email_change',
    timestamp: tMinus10m,
    ip_address: '203.0.113.88',
    context: {
      geo_country: 'RU',
      geo_region: 'MOW',
      device_fingerprint: 'fp_fixture_unrecognized_device_99'
    },
    metadata: { action_sensitivity: 'high' }
  });

  await SecurityEvent.create({
    event_id: EVENT_4_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    event_type: 'password_change',
    timestamp: tMinus5m,
    ip_address: '203.0.113.88',
    context: {
      geo_country: 'RU',
      geo_region: 'MOW',
      device_fingerprint: 'fp_fixture_unrecognized_device_99'
    },
    metadata: { action_sensitivity: 'critical' }
  });

  // Additional session_terminated event with security_containment reason
  await SecurityEvent.create({
    event_id: EVENT_5_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    event_type: 'session_terminated',
    timestamp: tMinus5m,
    metadata: { reason: 'security_containment' }
  });

  // 5. ActionSequence & SequenceEvent
  const seq = await ActionSequence.create({
    id: SEQUENCE_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    started_at: tMinus10m,
    last_event_at: tMinus5m,
    event_count: 2
  });

  await SequenceEvent.create({
    sequence_id: seq.id,
    event_id: EVENT_3_ID,
    step_order: 1,
    added_at: tMinus10m
  });

  await SequenceEvent.create({
    sequence_id: seq.id,
    event_id: EVENT_4_ID,
    step_order: 2,
    added_at: tMinus5m
  });

  // 6. Risk Assessments
  await RiskAssessment.create({
    id: ASSESSMENT_1_ID,
    event_id: EVENT_1_ID,
    user_id: user1.id,
    session_id: SESSION_1_ID,
    risk_score: 15,
    risk_tier: 'low',
    contributing_signals: [
      { signal: 'known_device', category: 'device', weight: -10 },
      { signal: 'normal_travel', category: 'location', weight: 0 }
    ],
    evaluated_at: tMinus30m,
    explanation: {
      user_facing: 'Login from recognized corporate device in regular location.',
      admin_facing: 'Device fingerprint matched baseline. Location consistent with historical baseline.'
    }
  });

  await RiskAssessment.create({
    id: ASSESSMENT_2_ID,
    event_id: EVENT_4_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    risk_score: 88,
    risk_tier: 'critical',
    contributing_signals: [
      { signal: 'seq_rapid_credential_cascade', category: 'sequence', weight: 35 },
      { signal: 'unrecognized_device', category: 'device', weight: 25 },
      { signal: 'impossible_travel', category: 'location', weight: 28 }
    ],
    evaluated_at: tMinus5m,
    explanation: {
      user_facing: 'Critical security anomaly detected. Action blocked and session contained to safeguard your account.',
      admin_facing: 'Rapid credential modification sequence from unrecognized hardware fingerprint combined with impossible travel (velocity > 1200 km/h).'
    }
  });

  // Additional assessments to populate all tiers for overview
  await RiskAssessment.create({
    id: 'ra_fixture_03_medium',
    event_id: EVENT_2_ID,
    user_id: user2.id,
    session_id: SESSION_3_ID,
    risk_score: 45,
    risk_tier: 'medium',
    contributing_signals: [{ signal: 'unrecognized_device', category: 'device', weight: 45 }],
    evaluated_at: tMinus20m,
    explanation: { user_facing: 'Activity from new device.', admin_facing: 'Device novelty observed.' }
  });

  await RiskAssessment.create({
    id: 'ra_fixture_04_high',
    event_id: EVENT_3_ID,
    user_id: user2.id,
    session_id: SESSION_3_ID,
    risk_score: 68,
    risk_tier: 'high',
    contributing_signals: [
      { signal: 'unrecognized_country', category: 'location', weight: 40 },
      { signal: 'unrecognized_device', category: 'device', weight: 28 }
    ],
    evaluated_at: tMinus10m,
    explanation: { user_facing: 'Elevated location risk.', admin_facing: 'New country and unrecognized device.' }
  });

  // 7. Policy Decisions
  await PolicyDecision.create({
    id: DECISION_1_ID,
    event_id: EVENT_1_ID,
    risk_assessment_id: ASSESSMENT_1_ID,
    user_id: user1.id,
    session_id: SESSION_1_ID,
    action_type: 'login',
    action_sensitivity: 'low',
    risk_score: 15,
    risk_tier: 'low',
    recommended_decision: 'allow',
    effective_decision: 'allow',
    enforcement_outcome: 'allowed',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    reasons: [
      { source: 'base_matrix', rule_id: 'base_matrix.low.low', decision: 'allow' }
    ],
    contributing_signals: [
      { signal: 'known_device', category: 'device', weight: -10 }
    ],
    decided_at: tMinus30m,
    explanation: {
      user_facing: 'Sign-in permitted.',
      admin_facing: 'Low risk action evaluated against base matrix: allowed.'
    }
  });

  await PolicyDecision.create({
    id: DECISION_2_ID,
    event_id: EVENT_4_ID,
    risk_assessment_id: ASSESSMENT_2_ID,
    user_id: user1.id,
    session_id: SESSION_2_ID,
    action_type: 'password_change',
    action_sensitivity: 'critical',
    risk_score: 88,
    risk_tier: 'critical',
    recommended_decision: 'block',
    effective_decision: 'block',
    enforcement_outcome: 'contained_and_blocked',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    reasons: [
      {
        source: 'escalation_rules',
        rule_id: 'critical_takeover_containment',
        decision: 'block',
        reason: 'Rapid credential cascade and impossible travel on critical sensitive action'
      },
      {
        source: 'base_matrix',
        rule_id: 'base_matrix.critical.critical',
        decision: 'block'
      }
    ],
    contributing_signals: [
      { signal: 'seq_rapid_credential_cascade', category: 'sequence', weight: 35 },
      { signal: 'unrecognized_device', category: 'device', weight: 25 },
      { signal: 'impossible_travel', category: 'location', weight: 28 }
    ],
    decided_at: tMinus5m,
    explanation: {
      user_facing: 'Password modification halted. Session terminated due to critical risk escalation.',
      admin_facing: 'Escalation rule critical_takeover_containment triggered: contained_and_blocked outcome applied.'
    }
  });

  // Additional decisions to populate all outcome buckets for overview: monitor, reverify, delay, block
  await PolicyDecision.create({
    id: 'dec_fixture_03_monitor',
    user_id: user2.id,
    session_id: SESSION_3_ID,
    action_type: 'login',
    action_sensitivity: 'low',
    risk_score: 25,
    risk_tier: 'low',
    recommended_decision: 'monitor',
    effective_decision: 'monitor',
    enforcement_outcome: 'monitored',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    decided_at: tMinus20m
  });

  await PolicyDecision.create({
    id: 'dec_fixture_04_reverify',
    user_id: user2.id,
    session_id: SESSION_3_ID,
    action_type: 'recovery_email_change',
    action_sensitivity: 'high',
    risk_score: 55,
    risk_tier: 'medium',
    recommended_decision: 'reverify',
    effective_decision: 'reverify',
    enforcement_outcome: 'step_up_challenged',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    decided_at: tMinus15m
  });

  await PolicyDecision.create({
    id: 'dec_fixture_05_delay',
    user_id: user2.id,
    session_id: SESSION_3_ID,
    action_type: 'password_reset',
    action_sensitivity: 'high',
    risk_score: 72,
    risk_tier: 'high',
    recommended_decision: 'delay',
    effective_decision: 'delay',
    enforcement_outcome: 'delayed',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    decided_at: tMinus10m
  });

  await PolicyDecision.create({
    id: 'dec_fixture_06_block',
    user_id: user3.id,
    action_type: 'password_change',
    action_sensitivity: 'critical',
    risk_score: 95,
    risk_tier: 'critical',
    recommended_decision: 'block',
    effective_decision: 'block',
    enforcement_outcome: 'blocked',
    enforcement_mode: 'automatic',
    policy_version: 'default-v1@1.0.0',
    decided_at: tMinus1h
  });
}

/**
 * Executes HTTP requests against the running app in test environment
 * and writes captured responses to docs/api-examples/.
 *
 * @param {object} [options={}]
 * @param {string} [options.outputDir] - Target output directory
 * @returns {Promise<Record<string, any>>} Map of endpoint names to response bodies
 */
async function captureApiExamples(options = {}) {
  const outputDir = options.outputDir || path.resolve(__dirname, '../docs/api-examples');

  process.env.ACTIONGUARD_ADMIN_API_KEY = TEST_ADMIN_KEY;

  await seedFixtureData();

  // Obtain admin token
  const loginRes = await request(app)
    .post('/api/v1/admin/auth/login')
    .send({ admin_key: TEST_ADMIN_KEY });

  if (loginRes.status !== 200 || !loginRes.body.admin_token) {
    throw new Error(`Admin login failed with status ${loginRes.status}: ${JSON.stringify(loginRes.body)}`);
  }

  const adminToken = loginRes.body.admin_token;

  // 1. GET /api/v1/admin/overview?window=24h
  const overview24hRes = await request(app)
    .get('/api/v1/admin/overview?window=24h')
    .set('Authorization', `Bearer ${adminToken}`);
  if (overview24hRes.status !== 200) {
    throw new Error(`GET /admin/overview?window=24h failed: ${overview24hRes.status}`);
  }

  // 2. GET /api/v1/admin/overview?window=7d
  const overview7dRes = await request(app)
    .get('/api/v1/admin/overview?window=7d')
    .set('Authorization', `Bearer ${adminToken}`);
  if (overview7dRes.status !== 200) {
    throw new Error(`GET /admin/overview?window=7d failed: ${overview7dRes.status}`);
  }

  // 3. GET /api/v1/admin/users
  const usersRes = await request(app)
    .get('/api/v1/admin/users')
    .set('Authorization', `Bearer ${adminToken}`);
  if (usersRes.status !== 200) {
    throw new Error(`GET /admin/users failed: ${usersRes.status}`);
  }

  // 4. GET /api/v1/admin/users/:id/events
  const eventsRes = await request(app)
    .get(`/api/v1/admin/users/${DEMO_USER_ID}/events`)
    .set('Authorization', `Bearer ${adminToken}`);
  if (eventsRes.status !== 200) {
    throw new Error(`GET /admin/users/:id/events failed: ${eventsRes.status}`);
  }

  // 5. GET /api/v1/admin/users/:id/risk-history
  const riskHistoryRes = await request(app)
    .get(`/api/v1/admin/users/${DEMO_USER_ID}/risk-history`)
    .set('Authorization', `Bearer ${adminToken}`);
  if (riskHistoryRes.status !== 200) {
    throw new Error(`GET /admin/users/:id/risk-history failed: ${riskHistoryRes.status}`);
  }

  // 6. GET /api/v1/admin/users/:id/decisions
  const decisionsRes = await request(app)
    .get(`/api/v1/admin/users/${DEMO_USER_ID}/decisions`)
    .set('Authorization', `Bearer ${adminToken}`);
  if (decisionsRes.status !== 200) {
    throw new Error(`GET /admin/users/:id/decisions failed: ${decisionsRes.status}`);
  }

  // 7. GET /api/v1/admin/users/:id/sessions
  const sessionsRes = await request(app)
    .get(`/api/v1/admin/users/${DEMO_USER_ID}/sessions`)
    .set('Authorization', `Bearer ${adminToken}`);
  if (sessionsRes.status !== 200) {
    throw new Error(`GET /admin/users/:id/sessions failed: ${sessionsRes.status}`);
  }

  // 8. GET /api/v1/admin/users/:id/sequence
  const sequenceRes = await request(app)
    .get(`/api/v1/admin/users/${DEMO_USER_ID}/sequence`)
    .set('Authorization', `Bearer ${adminToken}`);
  if (sequenceRes.status !== 200) {
    throw new Error(`GET /admin/users/:id/sequence failed: ${sequenceRes.status}`);
  }

  // 9. GET /api/v1/admin/policy
  const policyRes = await request(app)
    .get('/api/v1/admin/policy')
    .set('Authorization', `Bearer ${adminToken}`);
  if (policyRes.status !== 200) {
    throw new Error(`GET /admin/policy failed: ${policyRes.status}`);
  }

  const results = {
    'admin-overview-24h': overview24hRes.body,
    'admin-overview-7d': overview7dRes.body,
    'admin-users': usersRes.body,
    'admin-user-events': eventsRes.body,
    'admin-user-risk-history': riskHistoryRes.body,
    'admin-user-decisions': decisionsRes.body,
    'admin-user-sessions': sessionsRes.body,
    'admin-user-sequence': sequenceRes.body,
    'admin-policy': policyRes.body
  };

  // Write files: both canonical names (admin-*.json) and shorthand (*.json)
  const fileMappings = [
    { key: 'admin-overview-24h', names: ['admin-overview-24h.json', 'overview-24h.json'] },
    { key: 'admin-overview-7d', names: ['admin-overview-7d.json', 'overview-7d.json'] },
    { key: 'admin-users', names: ['admin-users.json', 'users.json'] },
    { key: 'admin-user-events', names: ['admin-user-events.json', 'user-events.json'] },
    { key: 'admin-user-risk-history', names: ['admin-user-risk-history.json', 'user-risk-history.json'] },
    { key: 'admin-user-decisions', names: ['admin-user-decisions.json', 'user-decisions.json'] },
    { key: 'admin-user-sessions', names: ['admin-user-sessions.json', 'user-sessions.json'] },
    { key: 'admin-user-sequence', names: ['admin-user-sequence.json', 'user-sequence.json'] },
    { key: 'admin-policy', names: ['admin-policy.json', 'policy.json'] }
  ];

  const shouldWrite = options.writeToDisk ?? (process.env.REGENERATE_FIXTURES === 'true' || require.main === module);

  if (shouldWrite) {
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }
    for (const mapping of fileMappings) {
      const data = results[mapping.key];
      const jsonStr = JSON.stringify(data, null, 2) + '\n';
      for (const fileName of mapping.names) {
        fs.writeFileSync(path.join(outputDir, fileName), jsonStr, 'utf-8');
      }
    }

    // Write docs/api-examples/README.md with provenance and reproducibility
    const readmeContent = `# ActionGuard — Admin API Response Fixtures

This directory contains real JSON response fixtures captured directly from the ActionGuard backend in the test environment. These fixtures provide deterministic, contract-validated response examples to support development and testing of **Module 12c-1 (Admin Console & Explanation Graph)**.

## Provenance & Capture Method

- **Method**: Captured from real HTTP responses generated by the running Express application against the test MySQL database and test Redis instance.
- **Generator**: \`scripts/generate-api-examples.js\`
- **Automated Test**: \`tests/api-fixtures-capture.test.js\`
- **Environment**: Node.js v18+, test MySQL database (port 3307 or \`DB_PORT\`), test Redis / in-memory client.

## Fixture Verification vs. Intentional Regeneration

- **Verification Mode (Default)**: Normal test runs (\`npm test\`) execute live API response capture strictly in-memory and compare them against committed fixture files using strict contract comparison with timestamp normalization. Normal test runs **never** overwrite committed fixture files on disk.
- **Regeneration Mode**: To intentionally regenerate fixture files after an intentional API contract or schema change, set \`REGENERATE_FIXTURES=true\`:
  \`\`\`bash
  REGENERATE_FIXTURES=true npm test -- tests/api-fixtures-capture.test.js
  \`\`\`
  Or execute the standalone generation script directly:
  \`\`\`bash
  node scripts/generate-api-examples.js
  \`\`\`

## Endpoint & Fixture Mapping

| Endpoint | Fixture File | Shorthand Alias | Description |
|---|---|---|---|
| \`GET /api/v1/admin/overview?window=24h\` | \`admin-overview-24h.json\` | \`overview-24h.json\` | 24-hour SQL aggregates: decisions by outcome, assessments by tier, active/contained sessions |
| \`GET /api/v1/admin/overview?window=7d\` | \`admin-overview-7d.json\` | \`overview-7d.json\` | 7-day SQL aggregates |
| \`GET /api/v1/admin/users\` | \`admin-users.json\` | \`users.json\` | Paginated user accounts with active session counts and latest risk tiers |
| \`GET /api/v1/admin/users/:id/events\` | \`admin-user-events.json\` | \`user-events.json\` | User security events with \`device_ref\` and coarse geographic location |
| \`GET /api/v1/admin/users/:id/risk-history\` | \`admin-user-risk-history.json\` | \`user-risk-history.json\` | Risk assessments with numeric \`risk_score\`, \`risk_tier\`, contributing signals with weights, and dual explanations |
| \`GET /api/v1/admin/users/:id/decisions\` | \`admin-user-decisions.json\` | \`user-decisions.json\` | Policy decisions with rule IDs, reasons, enforcement outcome, and graph linkage (\`risk_assessment_id\`, \`event_id\`) |
| \`GET /api/v1/admin/users/:id/sessions\` | \`admin-user-sessions.json\` | \`user-sessions.json\` | User sessions with latest risk details, active state, and device reference |
| \`GET /api/v1/admin/users/:id/sequence\` | \`admin-user-sequence.json\` | \`user-sequence.json\` | Active action sequence with ordered sequence events and action sensitivities |
| \`GET /api/v1/admin/policy\` | \`admin-policy.json\` | \`policy.json\` | Active policy definition (\`policies/default-v1.json\`) with base matrix and escalation rules |

## Explanation Graph Relationship Model

The fixtures provide full cross-entity coherence for the interactive explanation graph (React Flow / FR-35):

\`\`\`text
SecurityEvent (event_id)
      │
      ├──────────────────────┐
      ▼                      ▼
ActionSequence         Contributing Signals
(events in order)      (signal, category, weight)
                             │
                             ▼
                     RiskAssessment (id)
                     (risk_score, risk_tier, explanations)
                             │
                             ▼
                     PolicyDecision (decision_id)
                     (reasons, effective_decision, enforcement_outcome)
\`\`\`

- \`decisions[].risk_assessment_id\` links directly to \`risk-history[].id\`.
- \`decisions[].event_id\` and \`risk-history[].event_id\` link directly to \`events[].event_id\`.
- \`sequence.events[].event_id\` links directly to \`events[].event_id\`.
- \`decisions[].contributing_signals\` matches \`risk-history[].contributing_signals\`.
- \`decisions[].reasons\` references rules from \`policy.json\` (e.g. \`critical_takeover_containment\`, \`base_matrix.critical.critical\`).

## Security & Privacy Invariants

- **No Secrets**: Contains zero passwords, password hashes, admin API keys, or JWT secrets.
- **No Raw Identifiers**: IP addresses, device fingerprints, and GPS coordinates are strictly excluded; only coarse locations (\`country\`, \`region\`) and opaque SHA-256 prefixes (\`device_ref\`) are present.
- **No Tokens**: Admin session tokens (\`agadm_...\`) are used exclusively for authentication during capture and are never included in fixture files.
`;

    fs.writeFileSync(path.join(outputDir, 'README.md'), readmeContent, 'utf-8');
  }

  // Clean up admin tokens in redis
  const redis = getRedisClient();
  if (typeof redis.keys === 'function') {
    const keys = await redis.keys(`${REDIS_PREFIXES.ADMIN_TOKEN}*`);
    if (keys.length > 0) {
      await redis.del(...keys);
    }
  } else if (redis.store && typeof redis.store.clear === 'function') {
    redis.store.clear();
  }

  return results;
}

const ISO_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

/**
 * Normalizes genuinely dynamic fields (strict ISO-8601 date strings) for drift comparison.
 * Preserves all structural shapes, keys, types, numbers, booleans, and string values.
 *
 * @param {any} obj
 * @returns {any}
 */
function normalizeFixture(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    if (ISO_REGEX.test(obj) && !isNaN(Date.parse(obj))) {
      return '<ISO_8601_TIMESTAMP>';
    }
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(normalizeFixture);
  }
  if (typeof obj === 'object') {
    const copy = {};
    for (const key of Object.keys(obj).sort()) {
      copy[key] = normalizeFixture(obj[key]);
    }
    return copy;
  }
  return obj;
}

/**
 * Compares two JSON-compatible structures and returns a list of human-readable,
 * sanitized differences describing missing keys, extra keys, type mismatches,
 * and value divergences.
 *
 * @param {any} actual
 * @param {any} expected
 * @param {string} [path='$']
 * @returns {string[]} List of differences
 */
function findDifferences(actual, expected, path = '$') {
  const diffs = [];

  if (actual === expected) {
    return diffs;
  }

  if (actual === null || expected === null || actual === undefined || expected === undefined) {
    if (actual !== expected) {
      diffs.push(`Value mismatch at ${path}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
    }
    return diffs;
  }

  const actualType = Array.isArray(actual) ? 'array' : typeof actual;
  const expectedType = Array.isArray(expected) ? 'array' : typeof expected;

  if (actualType !== expectedType) {
    diffs.push(`Type mismatch at ${path}: expected ${expectedType}, received ${actualType}`);
    return diffs;
  }

  if (Array.isArray(actual)) {
    if (actual.length !== expected.length) {
      diffs.push(`Array length mismatch at ${path}: expected ${expected.length}, received ${actual.length}`);
    }
    const maxLen = Math.max(actual.length, expected.length);
    for (let i = 0; i < maxLen; i++) {
      if (i >= actual.length) {
        diffs.push(`Missing array element at ${path}[${i}]: expected ${JSON.stringify(expected[i])}`);
      } else if (i >= expected.length) {
        diffs.push(`Unexpected extra array element at ${path}[${i}]: received ${JSON.stringify(actual[i])}`);
      } else {
        diffs.push(...findDifferences(actual[i], expected[i], `${path}[${i}]`));
      }
    }
    return diffs;
  }

  if (typeof actual === 'object') {
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();

    const missingKeys = expectedKeys.filter((k) => !actual.hasOwnProperty(k));
    const extraKeys = actualKeys.filter((k) => !expected.hasOwnProperty(k));

    if (missingKeys.length > 0) {
      diffs.push(`Missing properties at ${path}: [${missingKeys.join(', ')}]`);
    }
    if (extraKeys.length > 0) {
      diffs.push(`Unexpected extra properties at ${path}: [${extraKeys.join(', ')}]`);
    }

    const commonKeys = actualKeys.filter((k) => expected.hasOwnProperty(k));
    for (const k of commonKeys) {
      diffs.push(...findDifferences(actual[k], expected[k], `${path}.${k}`));
    }
    return diffs;
  }

  if (actual !== expected) {
    diffs.push(`Value mismatch at ${path}: expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }

  return diffs;
}

if (require.main === module) {
  captureApiExamples()
    .then(() => {
      console.log('Successfully captured and wrote API fixtures to docs/api-examples/');
      process.exit(0);
    })
    .catch((err) => {
      console.error('Failed to capture API fixtures:', err);
      process.exit(1);
    });
}

module.exports = {
  captureApiExamples,
  seedFixtureData,
  normalizeFixture,
  findDifferences,
  DEMO_USER_ID,
  USER_2_ID,
  USER_3_ID,
  SESSION_1_ID,
  SESSION_2_ID,
  EVENT_1_ID,
  EVENT_4_ID,
  SEQUENCE_ID,
  ASSESSMENT_1_ID,
  ASSESSMENT_2_ID,
  DECISION_1_ID,
  DECISION_2_ID,
  TEST_ADMIN_KEY
};

