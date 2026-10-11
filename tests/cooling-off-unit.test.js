'use strict';

const crypto = require('crypto');
const { runMigrations } = require('../src/database/migrate');
const {
  User,
  Session,
  SecurityEvent,
  PolicyDecision,
  DelayedAction
} = require('../src/database/models');
const { createSession, invalidateSession } = require('../src/services/sessionService');
const coolingOffService = require('../src/services/coolingOffService');
const redisStorage = require('../src/storage/redis');
const riskEngineService = require('../src/services/riskEngineService');
const policyLoader = require('../src/services/policyLoader');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

describe('Module 10c — Cooling-Off Service Unit & Boundary Verification (FR-32)', () => {
  let user;
  let session;

  beforeAll(async () => {
    await runMigrations();
  });

  beforeEach(async () => {
    user = await User.create({
      email: `cooling-unit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}@example.com`,
      password_hash: 'hashed_pw_cooling_unit'
    });
    session = await createSession(user.id, user.email, 900);
  });

  afterEach(() => {
    coolingOffService.resetActionExecutors();
    jest.restoreAllMocks();
  });

  // T10c-01 (FR-32)
  test('T10c-01 (FR-32): DelayedAction model enforces schema validation, defaults to pending status, and binds to User, Session, and PolicyDecision', async () => {
    const dec = await PolicyDecision.create({
      id: `dec_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      risk_score: 55,
      risk_tier: 'high',
      recommended_decision: 'delay',
      effective_decision: 'delay',
      enforcement_outcome: 'delayed',
      enforcement_mode: 'automatic',
      policy_id: 'default',
      policy_version: 'default-v1@1.0.0',
      reasons: [{ rule_id: 'base_matrix.high.critical', decision: 'delay' }]
    });

    const tokenHash = crypto.createHash('sha256').update('test_token').digest('hex');
    const now = new Date();
    const executeAt = new Date(now.getTime() + 300 * 1000);
    const expiresAt = new Date(now.getTime() + 3900 * 1000);

    const action = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      decision_id: dec.id,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'purge_logs' },
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: tokenHash,
      scheduled_at: now,
      execute_at: executeAt,
      expires_at: expiresAt
    });

    expect(action.status).toBe('pending');
    expect(action.user_id).toBe(user.id);
    expect(action.session_id).toBe(session.sessionId);
    expect(action.decision_id).toBe(dec.id);

    // Verify associations
    const fetched = await DelayedAction.findByPk(action.id, {
      include: ['user', 'session', 'policyDecision']
    });
    expect(fetched.user.email).toBe(user.email);
    expect(fetched.session.id).toBe(session.sessionId);
    expect(fetched.policyDecision.id).toBe(dec.id);
  });

  // T10c-02 (FR-32)
  test('T10c-02 (FR-32): scheduleDelayedAction sanitizes credentials, generates unguessable cancellation token, stores SHA-256 hash in MySQL and Redis, and never stores plaintext token', async () => {
    const mockReq = {
      user: { id: user.id, email: user.email, session_id: session.sessionId },
      session: { sessionId: session.sessionId },
      method: 'POST',
      originalUrl: '/api/v1/account/high-impact',
      headers: {
        'x-forwarded-for': '203.0.113.195',
        'user-agent': 'CoolingOffTestAgent/1.0',
        'x-device-fingerprint': 'fp_cooling_test_01'
      },
      ip: '203.0.113.195',
      connection: { remoteAddress: '203.0.113.195' },
      body: {
        operation: 'export_full_database',
        target: 's3://backup-vault/export.tar.gz',
        password: 'PlainTextPasswordShouldBeStripped',
        current_password: 'ShouldAlsoBeStripped',
        new_password: 'MustNeverBePersisted'
      }
    };

    const decisionContext = {
      decisionRecord: { id: null, event_id: null },
      riskTier: 'high',
      routeSensitivity: 'critical',
      delaySeconds: 300
    };

    const { delayedAction, cancellationToken } = await coolingOffService.scheduleDelayedAction({
      req: mockReq,
      decisionContext,
      actionType: 'high_impact_action',
      delaySeconds: 300
    });

    expect(cancellationToken).toMatch(/^ctkn_[a-f0-9]{64}$/);
    expect(delayedAction.id).toMatch(/^cact_/);
    expect(delayedAction.status).toBe('pending');
    expect(delayedAction.cooling_off_seconds).toBe(300);

    // Verify plaintext password fields were completely stripped from persisted payload
    expect(delayedAction.action_payload.operation).toBe('export_full_database');
    expect(delayedAction.action_payload.target).toBe('s3://backup-vault/export.tar.gz');
    expect(delayedAction.action_payload.password).toBeUndefined();
    expect(delayedAction.action_payload.current_password).toBeUndefined();
    expect(delayedAction.action_payload.new_password).toBeUndefined();

    // Verify DB stores only the SHA-256 hash
    const dbRecord = await DelayedAction.findByPk(delayedAction.id);
    const expectedHash = crypto.createHash('sha256').update(cancellationToken).digest('hex');
    expect(dbRecord.cancellation_token_hash).toBe(expectedHash);
    expect(JSON.stringify(dbRecord)).not.toContain(cancellationToken);

    // Verify Redis cache
    const client = redisStorage.getRedisClient();
    const redisCached = await client.get(`${REDIS_PREFIXES.COOLING_OFF_ACTION}${delayedAction.id}`);
    expect(redisCached).not.toBeNull();
    expect(redisCached).not.toContain(cancellationToken);

    const tokenMapActionId = await client.get(`${REDIS_PREFIXES.COOLING_OFF_TOKEN_MAP}${expectedHash}`);
    expect(tokenMapActionId).toBe(delayedAction.id);

    const userActions = await client.smembers(`${REDIS_PREFIXES.COOLING_OFF_USER_INDEX}${user.id}`);
    expect(userActions).toContain(delayedAction.id);
  });

  // T10c-03 (FR-32)
  test('T10c-03 (FR-32): cancelDelayedAction enforces constant-time token comparison, rejects unauthorized caller, rejects replayed or wrong tokens, and cleans Redis mappings', async () => {
    const mockReq = {
      user: { id: user.id },
      headers: {},
      body: { operation: 'delete_cloud_cluster' }
    };

    const { delayedAction, cancellationToken } = await coolingOffService.scheduleDelayedAction({
      req: mockReq,
      decisionContext: { riskTier: 'high', routeSensitivity: 'critical', delaySeconds: 300 },
      actionType: 'high_impact_action'
    });

    // 1. Wrong owner attempt -> 403 forbidden
    const otherUser = await User.create({ email: `other-${Date.now()}@example.com`, password_hash: 'hash' });
    await expect(
      coolingOffService.cancelDelayedAction({
        actionId: delayedAction.id,
        cancellationToken,
        userId: otherUser.id
      })
    ).rejects.toMatchObject({
      status: 403,
      code: 'forbidden'
    });

    // 2. Wrong cancellation token -> 403 invalid_cancellation_token
    await expect(
      coolingOffService.cancelDelayedAction({
        actionId: delayedAction.id,
        cancellationToken: 'ctkn_0000000000000000000000000000000000000000000000000000000000000000',
        userId: user.id
      })
    ).rejects.toMatchObject({
      status: 403,
      code: 'invalid_cancellation_token'
    });

    // 3. Valid cancellation succeeds
    const cancelled = await coolingOffService.cancelDelayedAction({
      actionId: delayedAction.id,
      cancellationToken,
      userId: user.id,
      reason: 'User noticed suspicious timing'
    });
    expect(cancelled.status).toBe('cancelled');
    expect(cancelled.cancelled_by).toBe(user.id);
    expect(cancelled.cancellation_reason).toBe('User noticed suspicious timing');
    expect(cancelled.cancelled_at).not.toBeNull();

    // 4. Replaying cancellation on the already-cancelled action fails
    await expect(
      coolingOffService.cancelDelayedAction({
        actionId: delayedAction.id,
        cancellationToken,
        userId: user.id
      })
    ).rejects.toMatchObject({
      status: 409,
      code: 'action_already_cancelled'
    });

    // 5. Verify Redis token map was cleaned up
    const client = redisStorage.getRedisClient();
    const tokenHash = crypto.createHash('sha256').update(cancellationToken).digest('hex');
    const tokenMapVal = await client.get(`${REDIS_PREFIXES.COOLING_OFF_TOKEN_MAP}${tokenHash}`);
    expect(tokenMapVal).toBeNull();
  });

  // T10c-04 (FR-32)
  test('T10c-04 (FR-32): executeDelayedAction enforces cooling-off duration, rejects early execution before deadline, and prevents execution of cancelled actions', async () => {
    const mockReq = {
      user: { id: user.id },
      session: { sessionId: session.sessionId },
      headers: {},
      body: { phone_number: '+14155559090' }
    };

    const { delayedAction } = await coolingOffService.scheduleDelayedAction({
      req: mockReq,
      decisionContext: { riskTier: 'high', routeSensitivity: 'medium', delaySeconds: 300 },
      actionType: 'phone_number_change'
    });

    // 1. Attempting execution immediately (while still in cooling-off period) is rejected
    await expect(
      coolingOffService.executeDelayedAction({
        actionId: delayedAction.id
      })
    ).rejects.toMatchObject({
      status: 409,
      code: 'action_still_cooling_off'
    });

    // 2. Cancel the action
    const tokenHash = crypto.createHash('sha256').update('any_token').digest('hex');
    await DelayedAction.update({ status: 'cancelled' }, { where: { id: delayedAction.id } });

    // 3. Attempting execution on a cancelled action is rejected
    await expect(
      coolingOffService.executeDelayedAction({
        actionId: delayedAction.id,
        force: true
      })
    ).rejects.toMatchObject({
      status: 409,
      code: 'action_not_pending'
    });
  });

  // T10c-05 (FR-32)
  test('T10c-05 (FR-32): executeDelayedAction rejects expired actions past expires_at and transitions status to expired', async () => {
    const now = Date.now();
    const pastExecuteAt = new Date(now - 7200 * 1000);
    const pastExpiresAt = new Date(now - 3600 * 1000);

    const action = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'mfa_change',
      action_sensitivity: 'high',
      route_path: '/api/v1/account/mfa',
      route_method: 'POST',
      action_payload: { mfa_enabled: true },
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(now - 8000 * 1000),
      execute_at: pastExecuteAt,
      expires_at: pastExpiresAt,
      status: 'pending'
    });

    await expect(
      coolingOffService.executeDelayedAction({
        actionId: action.id
      })
    ).rejects.toMatchObject({
      status: 410,
      code: 'delayed_action_expired'
    });

    const refreshed = await DelayedAction.findByPk(action.id);
    expect(refreshed.status).toBe('expired');
  });

  // T10c-06 (FR-32)
  test('T10c-06 (FR-32): Zero Trust Pre-Execution Rechecks: rejects execution if user account is locked, session is invalidated, risk escalated, or policy blocked', async () => {
    const actionBase = {
      action_type: 'recovery_email_change',
      action_sensitivity: 'high',
      route_path: '/api/v1/account/recovery-email',
      route_method: 'POST',
      action_payload: { recovery_email: 'delayed-recovered@example.com' },
      scheduled_at_risk_tier: 'medium',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(Date.now() - 400 * 1000),
      execute_at: new Date(Date.now() - 50 * 1000),
      expires_at: new Date(Date.now() + 3600 * 1000),
      status: 'pending'
    };

    // Case a: User account is locked at execution time
    const lockedAction = await DelayedAction.create({
      ...actionBase,
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId
    });

    await User.update({ locked_until: new Date(Date.now() + 600 * 1000) }, { where: { id: user.id } });

    const lockedResult = await coolingOffService.executeDelayedAction({
      actionId: lockedAction.id,
      force: true
    });
    expect(lockedResult.status).toBe('rejected');
    expect(lockedResult.reason).toBe('user_account_locked');

    const dbLockedAction = await DelayedAction.findByPk(lockedAction.id);
    expect(dbLockedAction.status).toBe('rejected');
    expect(dbLockedAction.failure_reason).toBe('user_account_locked');

    // Unlock user for remaining cases
    await User.update({ locked_until: null }, { where: { id: user.id } });

    // Case b: Session is invalidated at execution time
    const invalidSessionAction = await DelayedAction.create({
      ...actionBase,
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId
    });

    await invalidateSession(session.sessionId);

    const sessionResult = await coolingOffService.executeDelayedAction({
      actionId: invalidSessionAction.id,
      force: true
    });
    expect(sessionResult.status).toBe('rejected');
    expect(sessionResult.reason).toBe('session_invalidated_or_expired');

    // Restore active session for Case c & d
    const activeSession = await createSession(user.id, user.email, 900);

    // Case c: Risk escalated above scheduled_at_risk_tier ('medium' -> 'critical')
    const riskRiseAction = await DelayedAction.create({
      ...actionBase,
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: activeSession.sessionId,
      scheduled_at_risk_tier: 'medium'
    });

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 85,
      risk_tier: 'critical',
      contributing_signals: [{ signal: 'impossible_travel', weight: 85 }]
    });

    const riskRiseResult = await coolingOffService.executeDelayedAction({
      actionId: riskRiseAction.id,
      force: true
    });
    expect(riskRiseResult.status).toBe('rejected');
    expect(riskRiseResult.reason).toMatch(/policy_recheck_blocked|risk_tier_increased/);

    // Case d: Policy recheck produces 'block'
    const blockPolicyAction = await DelayedAction.create({
      ...actionBase,
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: activeSession.sessionId,
      scheduled_at_risk_tier: 'high'
    });

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 95,
      risk_tier: 'critical',
      contributing_signals: [{ signal: 'seq_takeover_progression', weight: 95 }]
    });

    const blockPolicyResult = await coolingOffService.executeDelayedAction({
      actionId: blockPolicyAction.id,
      force: true
    });
    expect(blockPolicyResult.status).toBe('rejected');
    expect(blockPolicyResult.reason).toBe('policy_recheck_blocked');
  });

  // T10c-07 (FR-32)
  test('T10c-07 (FR-32): Concurrency safety: atomic claim ensures that concurrent execution calls allow exactly one worker to succeed and reject concurrent race attempts', async () => {
    const action = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'run_batch_migration' },
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(Date.now() - 400 * 1000),
      execute_at: new Date(Date.now() - 50 * 1000),
      expires_at: new Date(Date.now() + 3600 * 1000),
      status: 'pending'
    });

    // Fire 5 concurrent execution attempts
    const settled = await Promise.allSettled(
      Array.from({ length: 5 }, () =>
        coolingOffService.executeDelayedAction({
          actionId: action.id,
          force: true
        })
      )
    );

    const fulfilled = settled.filter((r) => r.status === 'fulfilled');
    const rejected = settled.filter((r) => r.status === 'rejected');

    // Exactly one worker must succeed
    expect(fulfilled).toHaveLength(1);
    expect(fulfilled[0].value.status).toBe('completed');

    // The other 4 must be rejected due to concurrent state conflict or non-pending status
    expect(rejected).toHaveLength(4);
    for (const rej of rejected) {
      expect(['concurrent_execution_conflict', 'action_not_pending']).toContain(rej.reason.code);
    }

    const finalRecord = await DelayedAction.findByPk(action.id);
    expect(finalRecord.status).toBe('completed');
  });

  // T10c-14 (FR-32 / C-01, C-02)
  test('T10c-14 (FR-32 / C-01, C-02): Recursive payload sanitization, strict per-action allowlisting, and unknown actionType rejection prevent nested secret persistence and no-op execution', async () => {
    // 1. Recursive sanitizePayload strips secrets across nested objects, arrays, and case variations
    const deeplyNested = {
      operation: 'rotate_keys',
      nested: {
        Password: 'secret1',
        CURRENT_PASSWORD: 'secret2',
        new_password_hash: '$2b$10$hash',
        ApiKey: 'key_123',
        api_key: 'key_456',
        client_secret: 'sec_789',
        otp: '123456',
        safeField: 'keep_me'
      },
      items: [
        { token: 'tok_abc', refresh_token: 'ref_xyz', label: 'item_1' },
        { private_key: 'pem_data', label: 'item_2' }
      ]
    };

    const sanitized = coolingOffService.sanitizePayload(deeplyNested);
    expect(sanitized.operation).toBe('rotate_keys');
    expect(sanitized.nested).toEqual({ safeField: 'keep_me' });
    expect(sanitized.items).toEqual([{ label: 'item_1' }, { label: 'item_2' }]);
    expect(JSON.stringify(sanitized)).not.toMatch(/secret|key_123|key_456|tok_abc|ref_xyz|123456|pem_data|\$2b\$/);

    // 2. Unknown actionType is rejected at scheduling time with 400 unsupported_action_type
    await expect(
      coolingOffService.scheduleDelayedAction({
        req: {
          user: { id: user.id, session_id: session.sessionId },
          session: { sessionId: session.sessionId },
          headers: {},
          body: { foo: 'bar' }
        },
        actionType: 'arbitrary_unapproved_action'
      })
    ).rejects.toMatchObject({
      status: 400,
      code: 'unsupported_action_type'
    });

    // 3. Malformed payload for an approved actionType is rejected with 400 invalid_request
    await expect(
      coolingOffService.scheduleDelayedAction({
        req: {
          user: { id: user.id, session_id: session.sessionId },
          session: { sessionId: session.sessionId },
          headers: {},
          body: { phone_number: 'not-an-e164-number' }
        },
        actionType: 'phone_number_change'
      })
    ).rejects.toMatchObject({
      status: 400,
      code: 'invalid_request'
    });

    // 4. Unsupported action_type in DB row fails closed in executeDelayedAction instead of silently succeeding
    const unknownRow = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'unknown_legacy_action',
      action_sensitivity: 'high',
      route_path: '/api/v1/account/unknown',
      route_method: 'POST',
      action_payload: {},
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(Date.now() - 400 * 1000),
      execute_at: new Date(Date.now() - 50 * 1000),
      expires_at: new Date(Date.now() + 3600 * 1000),
      status: 'pending'
    });

    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: []
    });

    await expect(
      coolingOffService.executeDelayedAction({
        actionId: unknownRow.id,
        force: true
      })
    ).rejects.toThrow(/Unsupported delayed action_type/);

    const failedRow = await DelayedAction.findByPk(unknownRow.id);
    expect(failedRow.status).toBe('failed');
    expect(failedRow.failure_reason).toMatch(/Unsupported delayed action_type/);
  });

  // T10c-15 (FR-32 / C-01, C-02)
  test('T10c-15 (FR-32 / C-01, C-02): Delayed password_change and recovery_email_change enforce domain validation, bcrypt hashing, session termination, and email normalization/collision checks', async () => {
    const bcrypt = require('bcrypt');
    const initialHash = await bcrypt.hash('CorrectCurrentPass!123', 10);
    await user.update({ password_hash: initialHash });

    // 1. Scheduling password_change with wrong current_password fails with 401 invalid_credentials
    await expect(
      coolingOffService.scheduleDelayedAction({
        req: {
          user: { id: user.id, session_id: session.sessionId },
          session: { sessionId: session.sessionId },
          headers: {},
          body: {
            current_password: 'WrongCurrentPassword!999',
            new_password: 'BrandNewSecurePassword!456'
          }
        },
        decisionContext: { riskTier: 'high', routeSensitivity: 'high', delaySeconds: 300 },
        actionType: 'password_change'
      })
    ).rejects.toMatchObject({
      status: 401,
      code: 'invalid_credentials'
    });

    // 2. Scheduling password_change with valid current_password hashes new_password and strips hash from public view
    const { delayedAction: pwAction } = await coolingOffService.scheduleDelayedAction({
      req: {
        user: { id: user.id, session_id: session.sessionId },
        session: { sessionId: session.sessionId },
        headers: {},
        body: {
          current_password: 'CorrectCurrentPass!123',
          new_password: 'BrandNewSecurePassword!456'
        }
      },
      decisionContext: { riskTier: 'high', routeSensitivity: 'high', delaySeconds: 300 },
      actionType: 'password_change'
    });

    expect(pwAction.action_payload).toEqual({ password_change_requested: true });
    expect(pwAction.action_payload.new_password_hash).toBeUndefined();
    expect(pwAction.action_payload.new_password).toBeUndefined();

    const publicLookup = await coolingOffService.getDelayedAction(pwAction.id);
    expect(publicLookup.action_payload).toEqual({ password_change_requested: true });
    expect(JSON.stringify(publicLookup)).not.toContain('BrandNewSecurePassword!456');
    expect(JSON.stringify(publicLookup)).not.toContain('$2b$');

    // Execute delayed password_change -> updates password_hash and terminates all user sessions
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 0,
      risk_tier: 'low',
      contributing_signals: []
    });

    const pwExecRes = await coolingOffService.executeDelayedAction({
      actionId: pwAction.id,
      force: true
    });
    expect(pwExecRes.status).toBe('completed');
    expect(pwExecRes.result.action).toBe('password_change');
    expect(pwExecRes.result.reauthentication_required).toBe(true);
    expect(pwExecRes.result.sessions_terminated).toBeGreaterThanOrEqual(1);

    const updatedUser = await User.findByPk(user.id);
    expect(await bcrypt.compare('BrandNewSecurePassword!456', updatedUser.password_hash)).toBe(true);

    const oldSessionRow = await Session.findByPk(session.sessionId);
    expect(oldSessionRow.is_active).toBe(false);

    // 3. Create fresh session for recovery_email_change normalization & collision tests
    const freshSession = await createSession(user.id, user.email, 900);

    // Rejects recovery_email matching primary email (case/whitespace-insensitive)
    await expect(
      coolingOffService.scheduleDelayedAction({
        req: {
          user: { id: user.id, session_id: freshSession.sessionId },
          session: { sessionId: freshSession.sessionId },
          headers: {},
          body: { recovery_email: `  ${user.email.toUpperCase()}  ` }
        },
        decisionContext: { riskTier: 'high', routeSensitivity: 'high', delaySeconds: 300 },
        actionType: 'recovery_email_change'
      })
    ).rejects.toMatchObject({
      status: 400,
      code: 'invalid_request'
    });

    // Normalizes valid recovery_email to lowercase trimmed string
    const { delayedAction: emailAction } = await coolingOffService.scheduleDelayedAction({
      req: {
        user: { id: user.id, session_id: freshSession.sessionId },
        session: { sessionId: freshSession.sessionId },
        headers: {},
        body: { recovery_email: '  SecOps.Recovery@Example.ORG  ' }
      },
      decisionContext: { riskTier: 'high', routeSensitivity: 'high', delaySeconds: 300 },
      actionType: 'recovery_email_change'
    });
    expect(emailAction.action_payload.recovery_email).toBe('secops.recovery@example.org');
  });

  // T10c-16 (FR-32 / C-03)
  test('T10c-16 (FR-32 / C-03): cancelDelayedAction enforces expires_at, transitions expired pending actions to expired, updates SecurityEvent, and throws 410 action_expired', async () => {
    const secEvent = await SecurityEvent.create({
      event_id: `evt_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      event_type: 'high_impact_action',
      occurred_at: new Date(Date.now() - 5000 * 1000),
      metadata: { action_status: 'delayed' }
    });

    const rawToken = 'ctkn_' + crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

    const expiredPending = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      event_id: secEvent.event_id,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'expired_cancel_attempt' },
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: tokenHash,
      scheduled_at: new Date(Date.now() - 5000 * 1000),
      execute_at: new Date(Date.now() - 4700 * 1000),
      expires_at: new Date(Date.now() - 10 * 1000),
      status: 'pending'
    });

    await expect(
      coolingOffService.cancelDelayedAction({
        actionId: expiredPending.id,
        cancellationToken: rawToken,
        userId: user.id
      })
    ).rejects.toMatchObject({
      status: 410,
      code: 'action_expired'
    });

    const refreshedAction = await DelayedAction.findByPk(expiredPending.id);
    expect(refreshedAction.status).toBe('expired');

    const refreshedEvent = await SecurityEvent.findByPk(secEvent.event_id);
    expect(refreshedEvent.metadata.action_status).toBe('expired');
  });

  // T10c-17 (FR-32 / C-04)
  test('T10c-17 (FR-32 / C-04): Crash recovery & stale executing reconciliation transitions stuck executing actions to failed without re-running mutations', async () => {
    const staleExecuting = await DelayedAction.create({
      id: `cact_${crypto.randomUUID()}`,
      user_id: user.id,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      route_path: '/api/v1/account/high-impact',
      route_method: 'POST',
      action_payload: { operation: 'crashed_worker_op' },
      scheduled_at_risk_tier: 'high',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(Date.now() - 600 * 1000),
      execute_at: new Date(Date.now() - 300 * 1000),
      expires_at: new Date(Date.now() + 3600 * 1000),
      status: 'executing',
      updated_at: new Date(Date.now() - 60 * 1000)
    });

    // Backdate updated_at in MySQL to simulate a worker that crashed 60s ago
    await DelayedAction.update(
      { updated_at: new Date(Date.now() - 60 * 1000) },
      { where: { id: staleExecuting.id } }
    );

    const mutationSpy = jest.fn();
    coolingOffService.registerActionExecutor('high_impact_action', mutationSpy);

    const reconciledCount = await coolingOffService.reconcileStaleExecutingActions(10000);
    expect(reconciledCount).toBeGreaterThanOrEqual(1);
    expect(mutationSpy).not.toHaveBeenCalled();

    const refreshed = await DelayedAction.findByPk(staleExecuting.id);
    expect(refreshed.status).toBe('failed');
    expect(refreshed.failure_reason).toBe('worker_execution_timeout_or_crash');
  });

  // T10c-18 (FR-32 / C-05, C-06)
  test('T10c-18 (FR-32 / C-05, C-06): Zero Trust pre-execution checks require valid bound session ownership/expiry, fail closed on Risk Engine unavailability, and enforce active policy delay/reverify and scoped elevation', async () => {
    const {
      createMockVerificationTicket,
      grantElevation
    } = require('../src/services/elevationService');

    const baseFields = {
      user_id: user.id,
      action_type: 'recovery_email_change',
      action_sensitivity: 'high',
      route_path: '/api/v1/account/recovery-email',
      route_method: 'POST',
      action_payload: { recovery_email: 'zt-check@example.com' },
      scheduled_at_risk_tier: 'medium',
      cooling_off_seconds: 300,
      cancellation_token_hash: 'dummyhash',
      scheduled_at: new Date(Date.now() - 400 * 1000),
      execute_at: new Date(Date.now() - 50 * 1000),
      expires_at: new Date(Date.now() + 3600 * 1000),
      status: 'pending'
    };

    // 1. Missing session_id (null) is rejected
    const nullSessionAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: null
    });
    const nullSessRes = await coolingOffService.executeDelayedAction({
      actionId: nullSessionAction.id,
      force: true
    });
    expect(nullSessRes).toEqual({
      status: 'rejected',
      reason: 'session_invalidated_or_expired'
    });

    // 2. Session owned by a different user is rejected
    const otherUser = await User.create({
      email: `other-sess-${Date.now()}@example.com`,
      password_hash: 'hash'
    });
    const otherSession = await createSession(otherUser.id, otherUser.email, 900);
    const mismatchedSessAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: otherSession.sessionId
    });
    const mismatchRes = await coolingOffService.executeDelayedAction({
      actionId: mismatchedSessAction.id,
      force: true
    });
    expect(mismatchRes).toEqual({
      status: 'rejected',
      reason: 'session_invalidated_or_expired'
    });

    // 3. Risk Engine unavailability fails closed (never treated as low risk)
    const unavailableRiskAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: session.sessionId
    });
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'unavailable',
      risk_score: null,
      risk_tier: null,
      contributing_signals: []
    });
    const unavailRes = await coolingOffService.executeDelayedAction({
      actionId: unavailableRiskAction.id,
      force: true
    });
    expect(unavailRes).toEqual({
      status: 'rejected',
      reason: 'risk_engine_unavailable'
    });

    // 4. Policy recheck returning 'delay' at the same numeric tier ('medium' with travel+novelty on critical) is rejected
    const stillDelayedAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: session.sessionId,
      action_type: 'high_impact_action',
      action_sensitivity: 'critical',
      action_payload: { operation: 'still_risky_op' },
      scheduled_at_risk_tier: 'medium'
    });
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 40,
      risk_tier: 'medium',
      contributing_signals: [
        { signal: 'impossible_travel', weight: 25 },
        { signal: 'unrecognized_device', weight: 15 }
      ]
    });
    const delayRecheckRes = await coolingOffService.executeDelayedAction({
      actionId: stillDelayedAction.id,
      force: true
    });
    expect(delayRecheckRes).toEqual({
      status: 'rejected',
      reason: 'policy_recheck_delayed'
    });

    // 5. Policy recheck returning 'reverify' at same tier ('medium' on 'high' sensitivity) without scoped elevation is rejected
    const reverifyNoElevAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: session.sessionId,
      scheduled_at_risk_tier: 'medium'
    });
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: []
    });
    const noElevRes = await coolingOffService.executeDelayedAction({
      actionId: reverifyNoElevAction.id,
      force: true
    });
    expect(noElevRes).toEqual({
      status: 'rejected',
      reason: 'step_up_elevation_required'
    });

    // 6. Granting valid 'account_recovery' scoped elevation at 'medium' tier allows 'reverify' recheck to succeed
    const ticket = createMockVerificationTicket({
      userId: user.id,
      sessionId: session.sessionId,
      scope: 'account_recovery'
    });
    await grantElevation({
      sessionId: session.sessionId,
      userId: user.id,
      scope: 'account_recovery',
      verificationTicket: ticket,
      grantedAtRiskTier: 'medium'
    });

    const reverifyWithElevAction = await DelayedAction.create({
      ...baseFields,
      id: `cact_${crypto.randomUUID()}`,
      session_id: session.sessionId,
      scheduled_at_risk_tier: 'medium'
    });
    jest.spyOn(riskEngineService, 'evaluateRisk').mockResolvedValueOnce({
      status: 'ok',
      risk_score: 35,
      risk_tier: 'medium',
      contributing_signals: []
    });
    const withElevRes = await coolingOffService.executeDelayedAction({
      actionId: reverifyWithElevAction.id,
      force: true
    });
    expect(withElevRes.status).toBe('completed');
    expect(withElevRes.result.recovery_email).toBe('zt-check@example.com');
  });
});

