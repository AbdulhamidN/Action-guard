const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { getActiveSequenceFromCache } = require('../services/sequenceCacheService');
const { getSequenceById } = require('../services/sequenceStorageService');
const { sendError } = require('../utils/errors');

const router = express.Router();

/**
 * GET /api/v1/sequences/current
 *
 * Retrieves the current active sequence and ordered event timeline for the authenticated user.
 * Reads from Redis active sequence cache first with transparent MySQL fallback.
 * Strictly scoped to the authenticated caller identity.
 */
router.get('/current', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id || req.user.user_id;
    if (!userId) {
      return sendError(res, 401, 'unauthorized', 'User identity could not be verified');
    }

    const activeSeq = await getActiveSequenceFromCache(userId);
    if (!activeSeq) {
      return res.status(200).json({ sequence: null });
    }

    // Retrieve full ordered events for the active sequence
    const fullSequence = await getSequenceById(activeSeq.id, { includeEvents: true });
    if (!fullSequence) {
      return res.status(200).json({ sequence: null });
    }

    // Map ordered events exposing strictly event_id, event_type, and timestamp
    const events = (fullSequence.sequenceEvents || []).map((se) => {
      const eventRecord = se.securityEvent;
      return {
        event_id: eventRecord ? eventRecord.event_id : se.event_id,
        event_type: eventRecord ? eventRecord.event_type : null,
        timestamp: eventRecord && eventRecord.timestamp instanceof Date
          ? eventRecord.timestamp.toISOString()
          : (eventRecord && eventRecord.timestamp ? new Date(eventRecord.timestamp).toISOString() : null)
      };
    });

    return res.status(200).json({
      sequence: {
        id: fullSequence.id,
        started_at: fullSequence.started_at instanceof Date
          ? fullSequence.started_at.toISOString()
          : new Date(fullSequence.started_at).toISOString(),
        last_event_at: fullSequence.last_event_at instanceof Date
          ? fullSequence.last_event_at.toISOString()
          : new Date(fullSequence.last_event_at).toISOString(),
        event_count: fullSequence.event_count,
        events
      }
    });
  } catch (error) {
    console.error('[Sequences API] Error retrieving current sequence:', error);
    return sendError(
      res,
      500,
      'internal_error',
      'An unexpected error occurred while retrieving current sequence'
    );
  }
});

module.exports = router;
