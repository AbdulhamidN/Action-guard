'use strict';

const {
  sequelize,
  WebhookEndpoint,
  WebhookDeliveryLog
} = require('../src/database/models');
const { runMigrations } = require('../src/database/migrate');
const migration009 = require('../src/database/migrations/009_webhooks');
const { REDIS_PREFIXES } = require('../src/config/sessionConfig');

describe('Module 11.2a — Webhook Models, Migration 009 & Redis Prefix Configuration', () => {
  beforeAll(async () => {
    await runMigrations();
  });

  afterEach(async () => {
    try {
      await WebhookDeliveryLog.destroy({ where: {} });
      await WebhookEndpoint.destroy({ where: {} });
    } catch {
      // Ignore if a test temporarily dropped tables and is about to restore them
    }
  });

  afterAll(async () => {
    await runMigrations();
  });

  test('T11.2a-01: WebhookEndpoint and WebhookDeliveryLog initialize with expected attributes, default IDs, and strict validations', async () => {
    expect(WebhookEndpoint).toBeDefined();
    expect(WebhookDeliveryLog).toBeDefined();
    expect(WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS).toEqual([
      'event.processed',
      'decision.recorded'
    ]);
    expect(WebhookDeliveryLog.DELIVERY_STATUSES).toEqual([
      'pending',
      'delivered',
      'failed'
    ]);

    // Valid WebhookEndpoint creation with default ID and timestamps
    const endpoint = await WebhookEndpoint.create({
      url: 'https://siem.example.com/webhooks/actionguard',
      subscribed_events: ['event.processed', 'decision.recorded'],
      description: 'Production SIEM Receiver',
      encrypted_secret: 'deadbeef0123456789abcdef',
      secret_iv: '00112233445566778899aabb',
      secret_auth_tag: 'ccddeeff00112233445566778899aabb',
      secret_prefix: 'whsec_8f9a1b2c',
      is_active: true
    });

    expect(endpoint.id).toMatch(/^whk_[0-9a-f-]{36}$/i);
    expect(endpoint.url).toBe('https://siem.example.com/webhooks/actionguard');
    expect(endpoint.subscribed_events).toEqual(['event.processed', 'decision.recorded']);
    expect(endpoint.is_active).toBe(true);
    expect(endpoint.created_at).toBeInstanceOf(Date);
    expect(endpoint.updated_at).toBeInstanceOf(Date);

    // Reject non-HTTPS URLs
    await expect(
      WebhookEndpoint.create({
        url: 'http://insecure.example.com/hook',
        subscribed_events: ['event.processed'],
        encrypted_secret: 'cipher',
        secret_iv: 'iv',
        secret_auth_tag: 'tag',
        secret_prefix: 'whsec_12345678'
      })
    ).rejects.toThrow(/https:\/\//i);

    // Reject unsupported subscribed_events
    await expect(
      WebhookEndpoint.create({
        url: 'https://siem.example.com/hook',
        subscribed_events: ['unknown.event'],
        encrypted_secret: 'cipher',
        secret_iv: 'iv',
        secret_auth_tag: 'tag',
        secret_prefix: 'whsec_12345678'
      })
    ).rejects.toThrow(/Invalid subscribed event/i);

    // Reject empty subscribed_events array
    await expect(
      WebhookEndpoint.create({
        url: 'https://siem.example.com/hook',
        subscribed_events: [],
        encrypted_secret: 'cipher',
        secret_iv: 'iv',
        secret_auth_tag: 'tag',
        secret_prefix: 'whsec_12345678'
      })
    ).rejects.toThrow(/non-empty array/i);

    // Valid WebhookDeliveryLog creation with default ID and status
    const log = await WebhookDeliveryLog.create({
      webhook_id: endpoint.id,
      event_type: 'event.processed',
      source_event_id: 'evt_test_123',
      status: 'delivered',
      attempt_count: 1,
      http_status: 200,
      delivered_at: new Date()
    });

    expect(log.id).toMatch(/^whdel_[0-9a-f-]{36}$/i);
    expect(log.webhook_id).toBe(endpoint.id);
    expect(log.status).toBe('delivered');
    expect(log.attempt_count).toBe(1);
    expect(log.http_status).toBe(200);
    expect(log.created_at).toBeInstanceOf(Date);

    // Verify WebhookDeliveryLog is strictly secret-free and payload-free in schema attributes
    const logAttributes = Object.keys(WebhookDeliveryLog.rawAttributes);
    expect(logAttributes).not.toContain('payload');
    expect(logAttributes).not.toContain('encrypted_secret');
    expect(logAttributes).not.toContain('secret');

    // Reject invalid delivery status
    await expect(
      WebhookDeliveryLog.create({
        webhook_id: endpoint.id,
        event_type: 'event.processed',
        status: 'invalid_status'
      })
    ).rejects.toThrow(/Invalid status/i);
  });

  test('T11.2a-02: Associations between WebhookEndpoint and WebhookDeliveryLog and ON DELETE CASCADE', async () => {
    const endpoint = await WebhookEndpoint.create({
      url: 'https://soc.example.com/events',
      subscribed_events: ['decision.recorded'],
      description: 'SOC Webhook',
      encrypted_secret: 'ciphertext_hex',
      secret_iv: 'iv_hex',
      secret_auth_tag: 'tag_hex',
      secret_prefix: 'whsec_abcdef12'
    });

    const log1 = await WebhookDeliveryLog.create({
      webhook_id: endpoint.id,
      event_type: 'decision.recorded',
      source_event_id: 'dec_001',
      status: 'delivered',
      attempt_count: 1,
      http_status: 202
    });

    const log2 = await WebhookDeliveryLog.create({
      webhook_id: endpoint.id,
      event_type: 'decision.recorded',
      source_event_id: 'dec_002',
      status: 'failed',
      attempt_count: 3,
      http_status: 503,
      error_code: 'HTTP_503'
    });

    // Query with association include from parent -> children
    const loadedEndpoint = await WebhookEndpoint.findByPk(endpoint.id, {
      include: [{ model: WebhookDeliveryLog, as: 'deliveryLogs' }]
    });
    expect(loadedEndpoint).not.toBeNull();
    expect(loadedEndpoint.deliveryLogs).toHaveLength(2);

    // Query with association include from child -> parent
    const loadedLog = await WebhookDeliveryLog.findByPk(log1.id, {
      include: [{ model: WebhookEndpoint, as: 'webhook' }]
    });
    expect(loadedLog).not.toBeNull();
    expect(loadedLog.webhook.id).toBe(endpoint.id);

    // Verify ON DELETE CASCADE removes associated delivery logs when endpoint is destroyed
    await endpoint.destroy();

    const remainingLogs = await WebhookDeliveryLog.findAll({
      where: { id: [log1.id, log2.id] }
    });
    expect(remainingLogs).toHaveLength(0);
  });

  test('T11.2a-03: Migration 009_webhooks supports down(), up(), and idempotent re-execution', async () => {
    const queryInterface = sequelize.getQueryInterface();

    // Execute down() and confirm both tables are dropped
    await migration009.down(queryInterface);
    let tables = await queryInterface.showAllTables();
    let tableNames = tables.map((t) =>
      typeof t === 'string' ? t : t.tableName || Object.values(t)[0]
    );
    expect(tableNames).not.toContain('webhook_delivery_logs');
    expect(tableNames).not.toContain('webhook_endpoints');

    // Execute down() a second time to verify safe idempotency when tables are already absent
    await expect(migration009.down(queryInterface)).resolves.not.toThrow();

    // Execute up() to recreate tables and indexes
    await migration009.up(queryInterface);
    tables = await queryInterface.showAllTables();
    tableNames = tables.map((t) =>
      typeof t === 'string' ? t : t.tableName || Object.values(t)[0]
    );
    expect(tableNames).toContain('webhook_endpoints');
    expect(tableNames).toContain('webhook_delivery_logs');

    // Execute up() and full runMigrations() again to verify idempotency on an already-migrated schema
    await expect(migration009.up(queryInterface)).resolves.not.toThrow();
    await expect(runMigrations()).resolves.not.toThrow();
  });

  test('T11.2a-04: REDIS_PREFIXES includes EXTERNAL_EVENT_IDEMPOTENCY namespace', () => {
    expect(REDIS_PREFIXES).toBeDefined();
    expect(REDIS_PREFIXES.EXTERNAL_EVENT_IDEMPOTENCY).toBe('ext_event_idem:');
    expect(Object.isFrozen(REDIS_PREFIXES)).toBe(true);
  });
});
