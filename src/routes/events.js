const express = require('express');
const { authenticateApiKey } = require('../middleware/auth');
const { SecurityEvent } = require('../database/models');
const { querySecurityEvents } = require('../services/eventService');
const { sendError } = require('../utils/errors');

const router = express.Router();

/**
 * GET /api/v1/events
 * Query historical security events by user, session, event_type, or time range.
 * Requires service-level API key authentication.
 */
router.get('/', authenticateApiKey, async (req, res) => {
  try {
    const { user_id, session_id, event_type, from, to, limit, offset } = req.query;

    const filters = {};

    if (user_id !== undefined) {
      if (typeof user_id !== 'string' || user_id.trim() === '') {
        return sendError(res, 400, 'invalid_request', 'user_id must be a non-empty string');
      }
      filters.user_id = user_id.trim();
    }

    if (session_id !== undefined) {
      if (typeof session_id !== 'string' || session_id.trim() === '') {
        return sendError(res, 400, 'invalid_request', 'session_id must be a non-empty string');
      }
      filters.session_id = session_id.trim();
    }

    if (event_type !== undefined) {
      if (!SecurityEvent.SUPPORTED_EVENT_TYPES.includes(event_type)) {
        return sendError(
          res,
          400,
          'invalid_event_type',
          `The event_type '${event_type}' is not a recognized event type.`
        );
      }
      filters.event_type = event_type;
    }

    let parsedFrom;
    if (from !== undefined) {
      parsedFrom = new Date(from);
      if (isNaN(parsedFrom.getTime())) {
        return sendError(res, 400, 'invalid_request', "The 'from' parameter must be a valid ISO 8601 date.");
      }
      filters.from = parsedFrom;
    }

    let parsedTo;
    if (to !== undefined) {
      parsedTo = new Date(to);
      if (isNaN(parsedTo.getTime())) {
        return sendError(res, 400, 'invalid_request', "The 'to' parameter must be a valid ISO 8601 date.");
      }
      filters.to = parsedTo;
    }

    if (parsedFrom && parsedTo && parsedFrom > parsedTo) {
      return sendError(
        res,
        400,
        'invalid_request',
        "The 'from' parameter must be earlier than or equal to 'to'."
      );
    }

    const pagination = {};
    if (limit !== undefined) {
      const parsedLimit = parseInt(limit, 10);
      if (isNaN(parsedLimit) || parsedLimit < 1) {
        return sendError(res, 400, 'invalid_request', 'limit must be a positive integer.');
      }
      pagination.limit = parsedLimit;
    }

    if (offset !== undefined) {
      const parsedOffset = parseInt(offset, 10);
      if (isNaN(parsedOffset) || parsedOffset < 0) {
        return sendError(res, 400, 'invalid_request', 'offset must be a non-negative integer.');
      }
      pagination.offset = parsedOffset;
    }

    const result = await querySecurityEvents(filters, pagination);
    return res.status(200).json(result);
  } catch (error) {
    console.error('Error querying security events:', error);
    return sendError(res, 500, 'internal_error', 'An unexpected error occurred while querying events.');
  }
});

module.exports = router;
