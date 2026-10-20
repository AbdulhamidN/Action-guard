'use strict';

const { Op } = require('sequelize');
const {
  User,
  Session,
  Device,
  SecurityEvent,
  RiskAssessment,
  PolicyDecision,
  ActionSequence,
  SequenceEvent,
  BehavioralBaseline
} = require('../database/models');
const { invalidateSequenceCache } = require('../services/sequenceCacheService');
const redisStorage = require('../storage/redis');
const { REDIS_PREFIXES } = require('../config/sessionConfig');

/**
 * Safely cleans up records belonging exclusively to a scenario execution run.
 *
 * Safety Invariants:
 * 1. Never performs broad or unbounded deletions (destroy with empty where).
 * 2. Requires a valid, scoped run identifier or demo user ID.
 * 3. Deletes in strict foreign-key dependency order.
 * 4. Safe and idempotent if run multiple times.
 * 5. Cleans up both MySQL tables and Redis sequence/session caches.
 *
 * @param {object} runContext - Object containing run resources or identifiers
 * @param {string} [runContext.userId] - Specific demo user ID
 * @param {string} [runContext.runId] - Unique scenario run ID
 * @param {Array<string>} [runContext.sessionIds]
 * @param {Array<string>} [runContext.eventIds]
 * @param {Array<string>} [runContext.decisionIds]
 * @param {Array<string>} [runContext.assessmentIds]
 * @param {Array<string>} [runContext.sequenceIds]
 * @param {Array<string>} [runContext.deviceIds]
 * @returns {Promise<{ success: boolean, removed: object }>}
 */
async function cleanupScenarioRun(runContext = {}) {
  if (!runContext || typeof runContext !== 'object') {
    throw new Error('[ScenarioCleanup] Invalid runContext: must be a non-null object');
  }

  const userId = runContext.userId || (runContext.resources_created && runContext.resources_created.userId);
  const runId = runContext.runId || runContext.run_id;

  // Strict safety check: Never clean up without an explicit user ID or run identifier
  if (!userId && !runId) {
    throw new Error(
      '[ScenarioCleanup] Refusing to clean up: either userId or runId must be provided'
    );
  }

  // Find users matching the run identifier if userId was not directly supplied
  let targetUserIds = [];
  if (userId) {
    targetUserIds = [userId];
  } else if (runId) {
    const matchingUsers = await User.findAll({
      attributes: ['id'],
      where: {
        email: { [Op.like]: `%${runId}%` }
      }
    });
    targetUserIds = matchingUsers.map((u) => u.id);
  }

  const removed = {
    decisions: 0,
    assessments: 0,
    sequenceEvents: 0,
    sequences: 0,
    events: 0,
    devices: 0,
    sessions: 0,
    baselines: 0,
    users: 0
  };

  if (targetUserIds.length === 0) {
    return { success: true, removed };
  }

  // 1. Delete Policy Decisions
  const decisionWhere = { user_id: { [Op.in]: targetUserIds } };
  removed.decisions = await PolicyDecision.destroy({ where: decisionWhere, force: true });

  // 2. Delete Risk Assessments
  const assessmentWhere = { user_id: { [Op.in]: targetUserIds } };
  removed.assessments = await RiskAssessment.destroy({ where: assessmentWhere, force: true });

  // 3. Delete Sequence Events and Action Sequences
  const userSequences = await ActionSequence.findAll({
    attributes: ['id'],
    where: { user_id: { [Op.in]: targetUserIds } }
  });
  const sequenceIds = userSequences.map((s) => s.id);

  if (sequenceIds.length > 0) {
    removed.sequenceEvents = await SequenceEvent.destroy({
      where: { sequence_id: { [Op.in]: sequenceIds } },
      force: true
    });
    removed.sequences = await ActionSequence.destroy({
      where: { id: { [Op.in]: sequenceIds } },
      force: true
    });
  }

  // 4. Delete Security Events
  removed.events = await SecurityEvent.destroy({
    where: { user_id: { [Op.in]: targetUserIds } },
    force: true
  });

  // 5. Delete Behavioral Baselines
  removed.baselines = await BehavioralBaseline.destroy({
    where: { user_id: { [Op.in]: targetUserIds } },
    force: true
  });

  // 6. Delete Devices
  removed.devices = await Device.destroy({
    where: { user_id: { [Op.in]: targetUserIds } },
    force: true
  });

  // 7. Delete Sessions (and clear Redis session records)
  const userSessions = await Session.findAll({
    attributes: ['id'],
    where: { user_id: { [Op.in]: targetUserIds } }
  });
  const sessionIds = userSessions.map((s) => s.id);

  removed.sessions = await Session.destroy({
    where: { user_id: { [Op.in]: targetUserIds } },
    force: true
  });

  // 8. Delete Users
  removed.users = await User.destroy({
    where: { id: { [Op.in]: targetUserIds } },
    force: true
  });

  // 9. Clean up Redis state
  try {
    const redis = typeof redisStorage.getRedisClient === 'function' ? redisStorage.getRedisClient() : null;
    for (const uid of targetUserIds) {
      await invalidateSequenceCache(uid);
      if (redis) {
        await redis.del(`${REDIS_PREFIXES.USER_SESSIONS}${uid}`);
        await redis.del(`rate_limit:auth:${uid}`);
      }
    }
    if (redis && sessionIds.length > 0) {
      for (const sid of sessionIds) {
        await redis.del(`${REDIS_PREFIXES.SESSION}${sid}`);
        await redis.del(`elevation:${sid}`);
      }
    }
  } catch (err) {
    // Redis cleanup warning without failing database cleanup
    console.warn('[ScenarioCleanup] Redis cleanup notice:', err.message);
  }

  return { success: true, removed };
}

module.exports = {
  cleanupScenarioRun
};
