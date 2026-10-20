const bcrypt = require('bcrypt');
const {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent,
  BehavioralBaseline,
  ActionSequence,
  SequenceEvent
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration004 = require('../src/database/migrations/004_action_sequences');
const {
  createSequence,
  attachEventToSequence,
  getSequenceById,
  getSequencesByUserId
} = require('../src/services/sequenceStorageService');
const {
  correlateEventIntoSequence
} = require('../src/services/sequenceGroupingService');

describe('Sub-module 5.1 — Sequence Data Model & Persistence', () => {
  let userA;
  let userB;
  let sessionA1;
  let sessionA2;
  let sessionB1;
  let eventA1;
  let eventA2;
  let eventA3;
  let eventB1;

  beforeAll(async () => {
    await runMigrations();

    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');

    const passwordHash = await bcrypt.hash('Password123!', 10);

    userA = await User.create({
      email: 'seq-user-a@example.com',
      password_hash: passwordHash
    });

    userB = await User.create({
      email: 'seq-user-b@example.com',
      password_hash: passwordHash
    });

    const now = new Date();
    const future = new Date(Date.now() + 3600000);

    sessionA1 = await Session.create({
      user_id: userA.id,
      expires_at: future
    });

    sessionA2 = await Session.create({
      user_id: userA.id,
      expires_at: future
    });

    sessionB1 = await Session.create({
      user_id: userB.id,
      expires_at: future
    });

    // Create events for userA in sessionA1
    eventA1 = await SecurityEvent.create({
      user_id: userA.id,
      session_id: sessionA1.id,
      event_type: 'login_success',
      timestamp: new Date(now.getTime() - 20000),
      context: { ip_address: '1.2.3.4', geo_country: 'US' },
      metadata: { action_sensitivity: 'low' }
    });

    // Create event for userA in sessionA2 (multi-session event chain)
    eventA2 = await SecurityEvent.create({
      user_id: userA.id,
      session_id: sessionA2.id,
      event_type: 'recovery_email_change',
      timestamp: new Date(now.getTime() - 10000),
      context: { ip_address: '1.2.3.4', geo_country: 'US' },
      metadata: { action_sensitivity: 'high' }
    });

    eventA3 = await SecurityEvent.create({
      user_id: userA.id,
      session_id: sessionA2.id,
      event_type: 'password_change',
      timestamp: now,
      context: { ip_address: '1.2.3.4', geo_country: 'US' },
      metadata: { action_sensitivity: 'critical' }
    });

    // Create event for userB in sessionB1
    eventB1 = await SecurityEvent.create({
      user_id: userB.id,
      session_id: sessionB1.id,
      event_type: 'login_success',
      timestamp: now,
      context: { ip_address: '5.6.7.8', geo_country: 'GB' },
      metadata: { action_sensitivity: 'low' }
    });
  });

  afterAll(async () => {
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 0');
    await SequenceEvent.destroy({ where: {}, force: true });
    await ActionSequence.destroy({ where: {}, force: true });
    await BehavioralBaseline.destroy({ where: {}, force: true });
    await SecurityEvent.destroy({ where: {}, force: true });
    await Device.destroy({ where: {}, force: true });
    await Session.destroy({ where: {}, force: true });
    await User.destroy({ where: {}, force: true });
    await sequelize.query('SET FOREIGN_KEY_CHECKS = 1');
  });

  describe('1. Stripped Grouping-Only Schema & Sequence Creation', () => {
    test('creates an action sequence with only grouping fields and default count', async () => {
      const sequence = await createSequence({
        user_id: userA.id,
        started_at: new Date('2026-05-01T10:00:00Z')
      });

      expect(sequence).not.toBeNull();
      expect(sequence.id).toMatch(/^seq_/);
      expect(sequence.user_id).toBe(userA.id);
      expect(sequence.session_id).toBeNull();
      expect(sequence.event_count).toBe(0);

      // Verify stripped schema: NO sequence_type, status, severity, confidence, completed_at, correlation_evidence
      expect(sequence.sequence_type).toBeUndefined();
      expect(sequence.status).toBeUndefined();
      expect(sequence.severity).toBeUndefined();
      expect(sequence.confidence).toBeUndefined();
      expect(sequence.completed_at).toBeUndefined();
      expect(sequence.correlation_evidence).toBeUndefined();
    });

    test('creates an action sequence with optional originating session reference', async () => {
      const sequence = await createSequence({
        user_id: userA.id,
        session_id: sessionA1.id,
        started_at: new Date('2026-05-01T10:00:00Z')
      });

      expect(sequence.session_id).toBe(sessionA1.id);
    });

    test('rejects creation when user_id is missing', async () => {
      await expect(createSequence({})).rejects.toThrow(/user_id is required/);
    });
  });

  describe('2. Multi-Session Event Chaining & Ordered Reconstruction', () => {
    test('attaches events spanning multiple sessions and reconstructs in deterministic order', async () => {
      const sequence = await createSequence({
        user_id: userA.id,
        session_id: sessionA1.id,
        started_at: eventA1.timestamp
      });

      // Attach step 1 from sessionA1
      const se1 = await attachEventToSequence(sequence.id, eventA1.event_id, 1);
      expect(se1.step_order).toBe(1);

      // Attach step 2 from sessionA2
      const se2 = await attachEventToSequence(sequence.id, eventA2.event_id, 2);
      expect(se2.step_order).toBe(2);

      // Attach step 3 from sessionA2
      const se3 = await attachEventToSequence(sequence.id, eventA3.event_id, 3);
      expect(se3.step_order).toBe(3);

      // Retrieve sequence with hydrated events
      const retrieved = await getSequenceById(sequence.id, { includeEvents: true });
      expect(retrieved.event_count).toBe(3);
      expect(retrieved.sequenceEvents).toHaveLength(3);

      // Verify deterministic step_order ASC
      expect(retrieved.sequenceEvents[0].step_order).toBe(1);
      expect(retrieved.sequenceEvents[0].event_id).toBe(eventA1.event_id);
      expect(retrieved.sequenceEvents[0].securityEvent.session_id).toBe(sessionA1.id);

      expect(retrieved.sequenceEvents[1].step_order).toBe(2);
      expect(retrieved.sequenceEvents[1].event_id).toBe(eventA2.event_id);
      expect(retrieved.sequenceEvents[1].securityEvent.session_id).toBe(sessionA2.id);

      expect(retrieved.sequenceEvents[2].step_order).toBe(3);
      expect(retrieved.sequenceEvents[2].event_id).toBe(eventA3.event_id);
      expect(retrieved.sequenceEvents[2].securityEvent.session_id).toBe(sessionA2.id);
    });
  });

  describe('3. Strict Single-User Isolation (Cross-User Event Rejection)', () => {
    test('strictly rejects attaching User B event to User A action sequence', async () => {
      const seqA = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      // eventB1 belongs to userB, seqA belongs to userA
      await expect(
        attachEventToSequence(seqA.id, eventB1.event_id, 1)
      ).rejects.toThrow(/Cross-user sequence violation/);

      // Verify no junction was created
      const seqCheck = await getSequenceById(seqA.id, { includeEvents: true });
      expect(seqCheck.event_count).toBe(0);
      expect(seqCheck.sequenceEvents).toHaveLength(0);
    });
  });

  describe('4. Database-Enforced Unique Constraints & Step Order Validation', () => {
    test('enforces UNIQUE(sequence_id, event_id) by rejecting duplicate event attachment', async () => {
      const seq = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await attachEventToSequence(seq.id, eventA1.event_id, 1);

      // Attempting to attach eventA1 again at step 2 must fail on unique constraint
      await expect(
        attachEventToSequence(seq.id, eventA1.event_id, 2)
      ).rejects.toThrow();
    });

    test('enforces database-level UNIQUE(sequence_id, step_order)', async () => {
      const seq1 = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await attachEventToSequence(seq1.id, eventA1.event_id, 1);

      // Attaching eventA2 to seq1 at duplicate step_order 1 must fail in DB
      await expect(
        attachEventToSequence(seq1.id, eventA2.event_id, 1)
      ).rejects.toThrow();

      // But using step_order 1 in a DIFFERENT sequence must succeed
      const seq2 = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      const seInSeq2 = await attachEventToSequence(seq2.id, eventA2.event_id, 1);
      expect(seInSeq2.step_order).toBe(1);
    });

    test('rejects non-positive step_order values', async () => {
      const seq = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await expect(attachEventToSequence(seq.id, eventA1.event_id, 0)).rejects.toThrow(
        /positive integer/
      );
      await expect(attachEventToSequence(seq.id, eventA1.event_id, -1)).rejects.toThrow(
        /positive integer/
      );
      await expect(attachEventToSequence(seq.id, eventA1.event_id, 1.5)).rejects.toThrow(
        /positive integer/
      );
    });
  });

  describe('5. Many-to-Many Event Sharing Across Sequences', () => {
    test('allows one SecurityEvent to participate in multiple distinct sequences', async () => {
      const seq1 = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      const seq2 = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await attachEventToSequence(seq1.id, eventA1.event_id, 1);
      await attachEventToSequence(seq2.id, eventA1.event_id, 1);

      const check1 = await getSequenceById(seq1.id, { includeEvents: true });
      const check2 = await getSequenceById(seq2.id, { includeEvents: true });

      expect(check1.sequenceEvents[0].event_id).toBe(eventA1.event_id);
      expect(check2.sequenceEvents[0].event_id).toBe(eventA1.event_id);
    });
  });

  describe('6. Source of Truth & Zero Secret/Coordinate Duplication', () => {
    test('sequence storage stores only references and grouping metadata, not raw event bodies or secrets', async () => {
      const seq = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await attachEventToSequence(seq.id, eventA1.event_id, 1);

      // Raw inspection of sequence_events columns
      const [rawRows] = await sequelize.query(
        `SELECT * FROM sequence_events WHERE sequence_id = '${seq.id}'`
      );
      expect(rawRows).toHaveLength(1);
      const row = rawRows[0];

      // Columns must only be id, sequence_id, event_id, step_order, added_at
      const columns = Object.keys(row);
      expect(columns.sort()).toEqual(
        ['id', 'sequence_id', 'event_id', 'step_order', 'added_at'].sort()
      );

      // Verify no password, token, context, or coordinates exist in sequence_events
      expect(row.context).toBeUndefined();
      expect(row.metadata).toBeUndefined();
      expect(row.latitude).toBeUndefined();
      expect(row.longitude).toBeUndefined();
      expect(row.token).toBeUndefined();
      expect(row.password).toBeUndefined();
    });
  });

  describe('7. Session Deletion ON DELETE SET NULL Behavior', () => {
    test('preserves action sequence and sets session_id to NULL when referenced session is deleted', async () => {
      const tempSession = await Session.create({
        user_id: userA.id,
        expires_at: new Date(Date.now() + 3600000)
      });

      const seq = await createSequence({
        user_id: userA.id,
        session_id: tempSession.id,
        started_at: new Date()
      });

      expect(seq.session_id).toBe(tempSession.id);

      // Delete the originating session
      await tempSession.destroy();

      // Sequence must still exist with session_id set to NULL
      const reloadedSeq = await getSequenceById(seq.id);
      expect(reloadedSeq).not.toBeNull();
      expect(reloadedSeq.session_id).toBeNull();
    });
  });

  describe('8. Cascade Deletion Behavior', () => {
    test('deleting an ActionSequence cascades to its sequence_events while leaving SecurityEvents intact', async () => {
      const seq = await createSequence({
        user_id: userA.id,
        started_at: new Date()
      });

      await attachEventToSequence(seq.id, eventA1.event_id, 1);

      // Delete sequence
      await seq.destroy();

      // Junction records should be cascade-deleted
      const junctions = await SequenceEvent.findAll({ where: { sequence_id: seq.id } });
      expect(junctions).toHaveLength(0);

      // SecurityEvent must still exist intact
      const eventIntact = await SecurityEvent.findByPk(eventA1.event_id);
      expect(eventIntact).not.toBeNull();
    });

    test('deleting a User cascades to their ActionSequences', async () => {
      const tempUser = await User.create({
        email: 'temp-seq-user@example.com',
        password_hash: await bcrypt.hash('Password123!', 10)
      });

      const seq = await createSequence({
        user_id: tempUser.id,
        started_at: new Date()
      });

      await tempUser.destroy();

      const seqCheck = await getSequenceById(seq.id);
      expect(seqCheck).toBeNull();
    });
  });

  describe('9. Automatic Grouping Decision Service (correlateEventIntoSequence)', () => {
    test('appends event to existing sequence if within window; starts a new sequence if outside window', async () => {
      const passwordHash = await bcrypt.hash('Password123!', 10);
      const groupUserA = await User.create({
        email: 'group-user-a@example.com',
        password_hash: passwordHash
      });
      const groupUserB = await User.create({
        email: 'group-user-b@example.com',
        password_hash: passwordHash
      });

      const baseTime = new Date('2026-06-01T12:00:00Z');

      // 1. First event for user A -> starts a new sequence
      const evt1 = await SecurityEvent.create({
        user_id: groupUserA.id,
        session_id: sessionA1.id,
        event_type: 'login_success',
        timestamp: baseTime,
        context: { ip_address: '1.2.3.4' }
      });

      const res1 = await correlateEventIntoSequence(evt1, { windowMs: 15 * 60 * 1000 });
      expect(res1.isNewSequence).toBe(true);
      expect(res1.stepOrder).toBe(1);
      expect(res1.sequence.event_count).toBe(1);

      const seq1Id = res1.sequence.id;

      // 2. Second event 5 minutes later -> within 15-minute window -> joins seq1
      const evt2Time = new Date(baseTime.getTime() + 5 * 60 * 1000);
      const evt2 = await SecurityEvent.create({
        user_id: groupUserA.id,
        session_id: sessionA1.id,
        event_type: 'recovery_email_change',
        timestamp: evt2Time,
        context: { ip_address: '1.2.3.4' }
      });

      const res2 = await correlateEventIntoSequence(evt2, { windowMs: 15 * 60 * 1000 });
      expect(res2.isNewSequence).toBe(false);
      expect(res2.sequence.id).toBe(seq1Id);
      expect(res2.stepOrder).toBe(2);
      expect(res2.sequence.event_count).toBe(2);

      // 3. Third event 20 minutes after event 2 -> exceeds 15-minute window -> starts new sequence
      const evt3Time = new Date(evt2Time.getTime() + 20 * 60 * 1000);
      const evt3 = await SecurityEvent.create({
        user_id: groupUserA.id,
        session_id: sessionA2.id,
        event_type: 'password_change',
        timestamp: evt3Time,
        context: { ip_address: '1.2.3.4' }
      });

      const res3 = await correlateEventIntoSequence(evt3, { windowMs: 15 * 60 * 1000 });
      expect(res3.isNewSequence).toBe(true);
      expect(res3.sequence.id).not.toBe(seq1Id);
      expect(res3.stepOrder).toBe(1);
      expect(res3.sequence.event_count).toBe(1);

      // 4. Fourth event for User B (within window of user A's events) -> isolates to User B and starts new sequence
      const evt4 = await SecurityEvent.create({
        user_id: groupUserB.id,
        session_id: sessionB1.id,
        event_type: 'login_success',
        timestamp: evt3Time,
        context: { ip_address: '5.6.7.8' }
      });

      const res4 = await correlateEventIntoSequence(evt4, { windowMs: 15 * 60 * 1000 });
      expect(res4.isNewSequence).toBe(true);
      expect(res4.sequence.user_id).toBe(groupUserB.id);
      expect(res4.sequence.id).not.toBe(res3.sequence.id);
      expect(res4.stepOrder).toBe(1);
    });
  });

  describe('10. Migration 004 Rollback & Index Tracking Safety', () => {
    test('Scenario A: Migration 004 creates composite index when missing and rolls it back cleanly', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Ensure index is removed first
      const indexesBefore = await queryInterface.showIndex('security_events').catch(() => []);
      if (indexesBefore.some((idx) => idx.name === 'idx_security_events_user_type_time')) {
        await queryInterface.removeIndex('security_events', 'idx_security_events_user_type_time');
      }
      migration004.resetCompositeIndexState();

      // Run migration up
      await migration004.up(queryInterface);
      expect(migration004.wasCompositeIndexCreated()).toBe(true);

      const indexesAfterUp = await queryInterface.showIndex('security_events');
      expect(indexesAfterUp.some((idx) => idx.name === 'idx_security_events_user_type_time')).toBe(true);

      // Run migration down
      await migration004.down(queryInterface);
      expect(migration004.wasCompositeIndexCreated()).toBe(false);

      const indexesAfterDown = await queryInterface.showIndex('security_events');
      expect(indexesAfterDown.some((idx) => idx.name === 'idx_security_events_user_type_time')).toBe(false);

      // Restore migration 004 up for subsequent operations
      await migration004.up(queryInterface);
    });

    test('Scenario B: Migration 004 preserves pre-existing composite index on down()', async () => {
      const queryInterface = sequelize.getQueryInterface();

      // Manually ensure composite index is created beforehand
      const existingIndexes = await queryInterface.showIndex('security_events').catch(() => []);
      if (!existingIndexes.some((idx) => idx.name === 'idx_security_events_user_type_time')) {
        await queryInterface.addIndex('security_events', ['user_id', 'event_type', 'timestamp'], {
          name: 'idx_security_events_user_type_time'
        });
      }

      migration004.resetCompositeIndexState();

      // Run migration up; since index already exists, wasCompositeIndexCreated remains false
      await migration004.up(queryInterface);
      expect(migration004.wasCompositeIndexCreated()).toBe(false);

      // Run migration down; pre-existing index must be preserved!
      await migration004.down(queryInterface);
      const indexesAfterDown = await queryInterface.showIndex('security_events');
      expect(indexesAfterDown.some((idx) => idx.name === 'idx_security_events_user_type_time')).toBe(true);

      // Restore migration 004 up
      await migration004.up(queryInterface);
    });
  });
});
