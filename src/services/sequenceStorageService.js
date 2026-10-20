const { ActionSequence, SequenceEvent, SecurityEvent, sequelize } = require('../database/models');

/**
 * Creates a new ActionSequence record.
 * Stripped to grouping-only fields.
 *
 * @param {object} sequenceData
 * @param {string} sequenceData.user_id - Required user ID
 * @param {string} [sequenceData.session_id] - Optional originating session ID
 * @param {Date|string} [sequenceData.started_at] - Sequence start timestamp
 * @param {Date|string} [sequenceData.last_event_at] - Timestamp of latest event
 * @returns {Promise<object>} The created ActionSequence record
 */
async function createSequence(sequenceData = {}) {
  if (!sequenceData.user_id || typeof sequenceData.user_id !== 'string' || sequenceData.user_id.trim() === '') {
    throw new Error('user_id is required to create an action sequence');
  }

  const startedAt = sequenceData.started_at ? new Date(sequenceData.started_at) : new Date();
  const lastEventAt = sequenceData.last_event_at ? new Date(sequenceData.last_event_at) : startedAt;

  const sequence = await ActionSequence.create({
    user_id: sequenceData.user_id.trim(),
    session_id: sequenceData.session_id || null,
    started_at: startedAt,
    last_event_at: lastEventAt,
    event_count: 0
  });

  return sequence;
}

/**
 * Attaches an existing SecurityEvent to an ActionSequence.
 *
 * Enforces:
 * 1. Existence of sequence and event.
 * 2. Strict single-user ownership: SecurityEvent.user_id === ActionSequence.user_id.
 * 3. Step order must be an integer >= 1.
 * 4. Step order uniqueness within the sequence (enforced in DB and validated).
 * 5. Event uniqueness within the sequence (enforced in DB and validated).
 * 6. Atomically increments sequence.event_count and updates last_event_at.
 *
 * @param {string} sequenceId - Target ActionSequence ID
 * @param {string} eventId - SecurityEvent ID to attach
 * @param {number} stepOrder - Positive 1-indexed order within sequence
 * @param {object} [options={}] - Additional update options (e.g. added_at)
 * @returns {Promise<object>} The created SequenceEvent junction record
 */
async function attachEventToSequence(sequenceId, eventId, stepOrder, options = {}) {
  if (!sequenceId || typeof sequenceId !== 'string') {
    throw new Error('sequence_id is required');
  }
  if (!eventId || typeof eventId !== 'string') {
    throw new Error('event_id is required');
  }

  const parsedStepOrder = parseInt(stepOrder, 10);
  if (isNaN(parsedStepOrder) || parsedStepOrder < 1 || !Number.isInteger(Number(stepOrder))) {
    throw new Error('step_order must be a positive integer greater than or equal to 1');
  }

  return sequelize.transaction(async (t) => {
    const sequence = await ActionSequence.findByPk(sequenceId, { transaction: t });
    if (!sequence) {
      throw new Error(`ActionSequence with id '${sequenceId}' not found`);
    }

    const event = await SecurityEvent.findByPk(eventId, { transaction: t });
    if (!event) {
      throw new Error(`SecurityEvent with id '${eventId}' not found`);
    }

    // STRICT SINGLE-USER INVARIANT
    if (event.user_id !== sequence.user_id) {
      throw new Error(
        `Cross-user sequence violation: SecurityEvent belongs to user '${event.user_id}', but ActionSequence belongs to user '${sequence.user_id}'`
      );
    }

    const sequenceEvent = await SequenceEvent.create(
      {
        sequence_id: sequenceId,
        event_id: eventId,
        step_order: parsedStepOrder,
        added_at: options.added_at ? new Date(options.added_at) : new Date()
      },
      { transaction: t }
    );

    // Increment count and update last_event_at
    const updatedCount = sequence.event_count + 1;
    const eventTime = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp);
    const newLastEventAt = eventTime > sequence.last_event_at ? eventTime : sequence.last_event_at;

    await sequence.update(
      {
        event_count: updatedCount,
        last_event_at: newLastEventAt
      },
      { transaction: t }
    );

    return sequenceEvent;
  });
}

/**
 * Retrieves an ActionSequence by ID, optionally including ordered SecurityEvents.
 *
 * @param {string} sequenceId
 * @param {object} [options={}]
 * @param {boolean} [options.includeEvents=false]
 * @returns {Promise<object|null>}
 */
async function getSequenceById(sequenceId, options = {}) {
  if (!sequenceId || typeof sequenceId !== 'string') {
    return null;
  }

  if (options.includeEvents) {
    const sequence = await ActionSequence.findByPk(sequenceId, {
      include: [
        {
          model: SequenceEvent,
          as: 'sequenceEvents',
          include: [
            {
              model: SecurityEvent,
              as: 'securityEvent'
            }
          ]
        }
      ],
      order: [[{ model: SequenceEvent, as: 'sequenceEvents' }, 'step_order', 'ASC']]
    });

    return sequence;
  }

  return ActionSequence.findByPk(sequenceId);
}

/**
 * Retrieves all sequences for a given user with deterministic pagination.
 *
 * @param {string} userId
 * @param {object} [pagination={}]
 * @param {number|string} [pagination.limit=50]
 * @param {number|string} [pagination.offset=0]
 * @returns {Promise<{ sequences: Array, total: number, limit: number, offset: number }>}
 */
async function getSequencesByUserId(userId, pagination = {}) {
  if (!userId || typeof userId !== 'string') {
    return { sequences: [], total: 0, limit: 50, offset: 0 };
  }

  const where = { user_id: userId.trim() };

  const rawLimit = parseInt(pagination.limit, 10);
  const limit = isNaN(rawLimit) ? 50 : Math.min(Math.max(rawLimit, 1), 100);

  const rawOffset = parseInt(pagination.offset, 10);
  const offset = isNaN(rawOffset) ? 0 : Math.max(rawOffset, 0);

  const { rows, count } = await ActionSequence.findAndCountAll({
    where,
    limit,
    offset,
    order: [
      ['last_event_at', 'DESC'],
      ['id', 'DESC']
    ]
  });

  return {
    sequences: rows,
    total: count,
    limit,
    offset
  };
}

/**
 * Retrieves the most recent sequence for a given user by last_event_at.
 *
 * @param {string} userId
 * @returns {Promise<object|null>}
 */
async function getLatestSequenceForUser(userId) {
  if (!userId || typeof userId !== 'string') {
    return null;
  }

  return ActionSequence.findOne({
    where: { user_id: userId.trim() },
    order: [
      ['last_event_at', 'DESC'],
      ['id', 'DESC']
    ]
  });
}

module.exports = {
  createSequence,
  attachEventToSequence,
  getSequenceById,
  getSequencesByUserId,
  getLatestSequenceForUser
};
