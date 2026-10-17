const express = require('express');
const crypto = require('crypto');
const { Op } = require('sequelize');
const { requireAdminToken } = require('../middleware/auth');
const { authRateLimiter, apiRateLimiter } = require('../middleware/rateLimiter');
const { createAdminToken, revokeAdminToken } = require('../services/adminTokenService');
const {
  User,
  Session,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  sequelize
} = require('../database/models');
const { getActivePolicy } = require('../services/policyLoader');
const {
  getLatestSequenceForUser,
  getSequenceById
} = require('../services/sequenceStorageService');
const {
  buildEventRecordedPayload,
  buildAdminDecisionPayload,
  buildAdminSessionPayload,
  buildAdminSequencePayload,
  buildAdminRiskPayload
} = require('../realtime/payloads');

const router = express.Router();

/**
 * Validates limit and before pagination query params.
 * @param {object} query
 * @param {string} timeField
 * @returns {{ limit: number, timeFilter?: object } | { error: string, message: string }}
 */
function parsePagination(query, timeField) {
  let limit = 50;
  if (query.limit !== undefined) {
    const parsed = Number(query.limit);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 200) {
      return {
        error: 'invalid_request',
        message: 'limit must be a positive integer <= 200'
      };
    }
    limit = parsed;
  }

  const result = { limit };

  if (query.before !== undefined) {
    if (typeof query.before !== 'string') {
      return {
        error: 'invalid_request',
        message: 'before must be a valid ISO 8601 timestamp'
      };
    }
    const beforeDate = new Date(query.before);
    if (isNaN(beforeDate.getTime())) {
      return {
        error: 'invalid_request',
        message: 'before must be a valid ISO 8601 timestamp'
      };
    }
    result.timeFilter = { [timeField]: { [Op.lt]: beforeDate } };
  }

  return result;
}

/**
 * Parses and validates duration window string (e.g. 1h, 24h, 7d).
 * Default 24h. Min 1m, Max 7d (604,800,000 ms).
 * @param {string} [windowStr='24h']
 * @returns {{ ms: number, raw: string } | null}
 */
function parseWindow(windowStr = '24h') {
  if (typeof windowStr !== 'string') return null;
  const match = windowStr.trim().match(/^(\d+)([mhd])$/i);
  if (!match) return null;
  const num = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();
  let ms = 0;
  if (unit === 'm') ms = num * 60 * 1000;
  else if (unit === 'h') ms = num * 60 * 60 * 1000;
  else if (unit === 'd') ms = num * 24 * 60 * 60 * 1000;
  if (ms < 60 * 1000 || ms > 7 * 24 * 60 * 60 * 1000) return null;
  return { ms, raw: windowStr.trim() };
}

// ---------------------------------------------------------------------------
// Admin Auth Endpoints
// ---------------------------------------------------------------------------

/**
 * POST /api/v1/admin/auth/login
 * Rate-limited via authRateLimiter.
 * Exchanges ACTIONGUARD_ADMIN_API_KEY for a short-lived admin session token.
 */
router.post('/auth/login', authRateLimiter, async (req, res) => {
  try {
    const { admin_key: adminKey } = req.body || {};
    const configuredKey = process.env.ACTIONGUARD_ADMIN_API_KEY;

    // Fail-safe constant-time evaluation:
    // Even if configuredKey is missing/short or adminKey is missing/non-string,
    // evaluate constant-time comparison against a dummy digest to prevent timing leakage.
    const validConfig = typeof configuredKey === 'string' && configuredKey.length >= 32;
    const dummy = '0'.repeat(64);
    const configuredDigest = crypto.createHash('sha256').update(validConfig ? configuredKey : dummy).digest();
    const providedDigest = crypto.createHash('sha256').update(typeof adminKey === 'string' ? adminKey : '').digest();

    const keysMatch = crypto.timingSafeEqual(configuredDigest, providedDigest);

    if (!validConfig || typeof adminKey !== 'string' || !keysMatch) {
      return res.status(401).json({
        error: 'unauthorized',
        message: 'Invalid admin credentials'
      });
    }

    const { admin_token: token, expires_at: expiresAt } = await createAdminToken();

    return res.status(200).json({
      admin_token: token,
      expires_at: expiresAt
    });
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to authenticate admin session'
    });
  }
});

/**
 * POST /api/v1/admin/auth/logout
 * Protected by requireAdminToken.
 * Revokes the admin session token.
 */
router.post('/auth/logout', requireAdminToken, async (req, res) => {
  try {
    await revokeAdminToken(req.adminToken);
    return res.status(200).json({ message: 'Logged out' });
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to revoke admin token'
    });
  }
});

// ---------------------------------------------------------------------------
// Admin Read Endpoints (requireAdminToken & apiRateLimiter)
// ---------------------------------------------------------------------------

/**
 * GET /api/v1/admin/users?search&limit&offset
 * Returns paginated users with prefix search on email, active sessions count, and latest risk tier.
 */
router.get('/users', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    let limit = 20;
    if (req.query.limit !== undefined) {
      const parsed = Number(req.query.limit);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > 100) {
        return res.status(400).json({
          error: 'invalid_request',
          message: 'limit must be a positive integer <= 100'
        });
      }
      limit = parsed;
    }

    let offset = 0;
    if (req.query.offset !== undefined) {
      const parsed = Number(req.query.offset);
      if (!Number.isInteger(parsed) || parsed < 0) {
        return res.status(400).json({
          error: 'invalid_request',
          message: 'offset must be a non-negative integer'
        });
      }
      offset = parsed;
    }

    const where = {};
    if (typeof req.query.search === 'string' && req.query.search.trim().length > 0) {
      const sanitized = req.query.search.trim().replace(/[%_\\]/g, '\\$&');
      where.email = { [Op.like]: `${sanitized}%` };
    }

    const total = await User.count({ where });
    const users = await User.findAll({
      where,
      order: [
        ['email', 'ASC'],
        ['id', 'ASC']
      ],
      limit,
      offset
    });

    if (users.length === 0) {
      return res.status(200).json({ users: [], total });
    }

    const userIds = users.map((u) => u.id);

    // Active session counts per user (bounded SQL aggregate)
    const sessionCounts = await Session.findAll({
      attributes: ['user_id', [sequelize.fn('COUNT', sequelize.col('id')), 'cnt']],
      where: {
        user_id: { [Op.in]: userIds },
        is_active: true,
        expires_at: { [Op.gt]: new Date() }
      },
      group: ['user_id'],
      raw: true
    });

    const sessionCountMap = new Map();
    for (const row of sessionCounts) {
      sessionCountMap.set(row.user_id, Number(row.cnt));
    }

    // Latest risk assessment per user (window function)
    const latestAssessments = await sequelize.query(
      `SELECT user_id, risk_tier, evaluated_at FROM (
         SELECT user_id, risk_tier, evaluated_at,
                ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY evaluated_at DESC, id DESC) as rn
         FROM risk_assessments
         WHERE user_id IN (?)
       ) t WHERE rn = 1`,
      {
        replacements: [userIds],
        type: sequelize.QueryTypes.SELECT
      }
    );

    const assessmentMap = new Map();
    for (const a of latestAssessments) {
      assessmentMap.set(a.user_id, a);
    }

    const userList = users.map((u) => {
      const latest = assessmentMap.get(u.id);
      const activeCount = sessionCountMap.get(u.id) || 0;

      return {
        id: u.id,
        email: u.email,
        created_at: u.created_at instanceof Date ? u.created_at.toISOString() : String(u.created_at),
        locked_until: u.locked_until
          ? u.locked_until instanceof Date
            ? u.locked_until.toISOString()
            : String(u.locked_until)
          : null,
        latest_risk_tier: latest?.risk_tier || null,
        latest_risk_at: latest?.evaluated_at
          ? latest.evaluated_at instanceof Date
            ? latest.evaluated_at.toISOString()
            : String(latest.evaluated_at)
          : null,
        active_sessions: activeCount
      };
    });

    return res.status(200).json({ users: userList, total });
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve users'
    });
  }
});

/**
 * GET /api/v1/admin/users/:id/events?limit&before
 * Returns full security events for a user.
 */
router.get('/users/:id/events', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'User not found' });
    }

    const pagination = parsePagination(req.query, 'timestamp');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: user.id,
      ...(pagination.timeFilter || {})
    };

    const events = await SecurityEvent.findAll({
      where,
      order: [
        ['timestamp', 'DESC'],
        ['event_id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = events.map((e) => buildEventRecordedPayload(e, null, { includeUserId: true, includeDeviceRef: true }));
    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve events'
    });
  }
});

/**
 * GET /api/v1/admin/users/:id/risk-history?limit&before
 * Returns full admin risk assessments for a user.
 */
router.get('/users/:id/risk-history', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'User not found' });
    }

    const pagination = parsePagination(req.query, 'evaluated_at');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: user.id,
      ...(pagination.timeFilter || {})
    };

    const assessments = await RiskAssessment.findAll({
      where,
      order: [
        ['evaluated_at', 'DESC'],
        ['id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = assessments.map((a) => {
      const payload = buildAdminRiskPayload(null, a);
      payload.id = a.id;
      return payload;
    });

    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve risk history'
    });
  }
});

/**
 * GET /api/v1/admin/users/:id/decisions?limit&before
 * Returns full admin policy decisions for a user.
 */
router.get('/users/:id/decisions', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'User not found' });
    }

    const pagination = parsePagination(req.query, 'decided_at');
    if (pagination.error) {
      return res.status(400).json({
        error: pagination.error,
        message: pagination.message
      });
    }

    const where = {
      user_id: user.id,
      ...(pagination.timeFilter || {})
    };

    const decisions = await PolicyDecision.findAll({
      where,
      order: [
        ['decided_at', 'DESC'],
        ['id', 'DESC']
      ],
      limit: pagination.limit
    });

    const payloads = decisions.map((d) => buildAdminDecisionPayload(d));
    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve decisions'
    });
  }
});

/**
 * GET /api/v1/admin/users/:id/sessions
 * Returns admin session list with risk details for a user.
 */
router.get('/users/:id/sessions', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'User not found' });
    }

    const sessions = await Session.findAll({
      where: { user_id: user.id },
      order: [
        ['created_at', 'DESC'],
        ['id', 'DESC']
      ]
    });

    if (sessions.length === 0) {
      return res.status(200).json([]);
    }

    const sessionIds = sessions.map((s) => s.id);
    const [assessments, events] = await Promise.all([
      RiskAssessment.findAll({
        where: {
          session_id: { [Op.in]: sessionIds }
        },
        order: [
          ['evaluated_at', 'DESC'],
          ['id', 'DESC']
        ]
      }),
      SecurityEvent.findAll({
        where: {
          session_id: { [Op.in]: sessionIds }
        },
        order: [
          ['timestamp', 'DESC'],
          ['event_id', 'DESC']
        ]
      })
    ]);

    const latestBySession = new Map();
    for (const a of assessments) {
      if (!latestBySession.has(a.session_id)) {
        latestBySession.set(a.session_id, a);
      }
    }

    const latestEventBySession = new Map();
    for (const e of events) {
      if (!latestEventBySession.has(e.session_id)) {
        latestEventBySession.set(e.session_id, e);
      }
    }

    const payloads = sessions.map((s) => {
      const latest = latestBySession.get(s.id) || null;
      const latestEv = latestEventBySession.get(s.id) || null;
      return buildAdminSessionPayload(s, latest, latestEv);
    });

    return res.status(200).json(payloads);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve sessions'
    });
  }
});

/**
 * GET /api/v1/admin/users/:id/sequence
 * Returns active sequence with ordered events for a user, or { sequence: null } if none.
 */
router.get('/users/:id/sequence', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'User not found' });
    }

    const latest = await getLatestSequenceForUser(user.id);
    if (!latest) {
      return res.status(200).json({ sequence: null });
    }

    const fullSequence = await getSequenceById(latest.id, { includeEvents: true });
    if (!fullSequence) {
      return res.status(200).json({ sequence: null });
    }

    const payload = buildAdminSequencePayload(fullSequence);
    return res.status(200).json({ sequence: payload });
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve sequence'
    });
  }
});

/**
 * GET /api/v1/admin/policy
 * Returns active policy summary from getActivePolicy().
 */
router.get('/policy', requireAdminToken, apiRateLimiter, (req, res) => {
  try {
    const activePolicy = getActivePolicy();
    return res.status(200).json(activePolicy);
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to load active policy'
    });
  }
});

/**
 * GET /api/v1/admin/overview?window=24h
 * Returns aggregate metrics for the dashboard using pure SQL aggregates.
 */
router.get('/overview', requireAdminToken, apiRateLimiter, async (req, res) => {
  try {
    const windowStr = req.query.window !== undefined ? String(req.query.window) : '24h';
    const parsed = parseWindow(windowStr);
    if (!parsed) {
      return res.status(400).json({
        error: 'invalid_request',
        message: 'Invalid window parameter. Must be between 1m and 7d.'
      });
    }

    const windowEnd = new Date();
    const windowStart = new Date(windowEnd.getTime() - parsed.ms);

    // 1. Decisions by outcome
    const [outcomeRows] = await sequelize.query(
      `SELECT CASE
         WHEN enforcement_outcome = 'contained_and_blocked' THEN 'contained_and_blocked'
         WHEN enforcement_outcome IN ('allowed', 'elevated_allowed', 'recommend_only_allowed', 'allow') THEN 'allow'
         WHEN enforcement_outcome IN ('monitored', 'monitor') THEN 'monitor'
         WHEN enforcement_outcome IN ('step_up_challenged', 'fail_safe_challenged', 'reverify') THEN 'reverify'
         WHEN enforcement_outcome IN ('delayed', 'delay') THEN 'delay'
         WHEN enforcement_outcome IN ('blocked', 'fail_safe_blocked', 'block') THEN 'block'
         ELSE effective_decision
       END AS bucket, COUNT(*) AS cnt
       FROM policy_decisions
       WHERE decided_at >= :windowStart AND decided_at <= :windowEnd
       GROUP BY bucket`,
      { replacements: { windowStart, windowEnd } }
    );

    const decisionsByOutcome = {
      allow: 0,
      monitor: 0,
      reverify: 0,
      delay: 0,
      block: 0,
      contained_and_blocked: 0
    };
    for (const row of outcomeRows) {
      if (row.bucket in decisionsByOutcome) {
        decisionsByOutcome[row.bucket] = Number(row.cnt);
      }
    }

    // 2. Assessments by tier
    const [tierRows] = await sequelize.query(
      `SELECT risk_tier, COUNT(*) AS cnt
       FROM risk_assessments
       WHERE evaluated_at >= :windowStart AND evaluated_at <= :windowEnd
       GROUP BY risk_tier`,
      { replacements: { windowStart, windowEnd } }
    );

    const assessmentsByTier = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };
    for (const row of tierRows) {
      if (row.risk_tier in assessmentsByTier) {
        assessmentsByTier[row.risk_tier] = Number(row.cnt);
      }
    }

    // 3. Active sessions count
    const [activeRows] = await sequelize.query(
      `SELECT COUNT(*) AS cnt
       FROM sessions
       WHERE is_active = 1 AND expires_at > NOW()`
    );
    const activeSessions = Number(activeRows[0]?.cnt || 0);

    // 4. Contained sessions count in window
    const [containedRows] = await sequelize.query(
      `SELECT COUNT(DISTINCT session_id) AS cnt FROM (
         SELECT session_id
         FROM policy_decisions
         WHERE enforcement_outcome = 'contained_and_blocked'
           AND session_id IS NOT NULL
           AND decided_at >= :windowStart AND decided_at <= :windowEnd
         UNION
         SELECT session_id
         FROM security_events
         WHERE event_type = 'session_terminated'
           AND session_id IS NOT NULL
           AND JSON_UNQUOTE(JSON_EXTRACT(metadata, '$.reason')) = 'security_containment'
           AND timestamp >= :windowStart AND timestamp <= :windowEnd
       ) t`,
      { replacements: { windowStart, windowEnd } }
    );
    const containedSessions = Number(containedRows[0]?.cnt || 0);

    return res.status(200).json({
      window: parsed.raw,
      window_start: windowStart.toISOString(),
      window_end: windowEnd.toISOString(),
      decisions_by_outcome: decisionsByOutcome,
      assessments_by_tier: assessmentsByTier,
      active_sessions: activeSessions,
      contained_sessions: containedSessions
    });
  } catch (err) {
    return res.status(500).json({
      error: 'internal_error',
      message: 'Failed to retrieve overview metrics'
    });
  }
});

module.exports = router;
