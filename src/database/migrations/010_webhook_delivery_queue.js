'use strict';

const { DataTypes } = require('sequelize');

/**
 * Migration: 010_webhook_delivery_queue
 *
 * Extends `webhook_delivery_logs` to support durable asynchronous queueing,
 * atomic worker lease claiming, retry backoff scheduling, and duplicate
 * delivery job prevention for Module 11.2c Stage 2A.
 *
 * Preserves:
 * - `status` ENUM('pending', 'delivered', 'failed')
 * - Payload-free and secret-free schema invariant
 * - Foreign key CASCADE semantics on `webhook_id`
 */
module.exports = {
  up: async (queryInterface) => {
    const columns = await queryInterface
      .describeTable('webhook_delivery_logs')
      .catch(() => null);

    if (!columns) {
      return;
    }

    if (!columns.next_attempt_at) {
      await queryInterface.addColumn('webhook_delivery_logs', 'next_attempt_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.last_attempt_at) {
      await queryInterface.addColumn('webhook_delivery_logs', 'last_attempt_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.locked_at) {
      await queryInterface.addColumn('webhook_delivery_logs', 'locked_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.locked_by) {
      await queryInterface.addColumn('webhook_delivery_logs', 'locked_by', {
        type: DataTypes.STRING(64),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.updated_at) {
      await queryInterface.addColumn('webhook_delivery_logs', 'updated_at', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!columns.updated_at || columns.updated_at.allowNull !== false) {
      await queryInterface.sequelize.query(
        'UPDATE `webhook_delivery_logs` SET `updated_at` = COALESCE(`created_at`, CURRENT_TIMESTAMP(3)) WHERE `updated_at` IS NULL'
      );
      await queryInterface.changeColumn('webhook_delivery_logs', 'updated_at', {
        type: DataTypes.DATE(3),
        allowNull: false
      });
    }

    const existingIndexes = await queryInterface
      .showIndex('webhook_delivery_logs')
      .catch(() => []);
    const indexNames = existingIndexes.map((idx) => idx.name);

    if (!indexNames.includes('idx_webhook_delivery_logs_queue_schedule')) {
      try {
        await queryInterface.addIndex(
          'webhook_delivery_logs',
          ['status', 'next_attempt_at'],
          {
            name: 'idx_webhook_delivery_logs_queue_schedule'
          }
        );
      } catch {}
    }

    if (!indexNames.includes('uq_webhook_delivery_logs_endpoint_event')) {
      try {
        await queryInterface.addIndex(
          'webhook_delivery_logs',
          ['webhook_id', 'event_type', 'source_event_id'],
          {
            name: 'uq_webhook_delivery_logs_endpoint_event',
            unique: true
          }
        );
      } catch {}
    }
  },

  down: async (queryInterface) => {
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) =>
      typeof t === 'string' ? t : t.tableName || Object.values(t)[0]
    );

    if (!tableNames.includes('webhook_delivery_logs')) {
      return;
    }

    const existingIndexes = await queryInterface
      .showIndex('webhook_delivery_logs')
      .catch(() => []);
    const indexNames = existingIndexes.map((idx) => idx.name);

    // Ensure the single-column FK backing index on webhook_id exists before dropping the composite unique index
    if (!indexNames.includes('idx_webhook_delivery_logs_webhook_id')) {
      try {
        await queryInterface.addIndex('webhook_delivery_logs', ['webhook_id'], {
          name: 'idx_webhook_delivery_logs_webhook_id'
        });
      } catch {}
    }

    if (indexNames.includes('uq_webhook_delivery_logs_endpoint_event')) {
      try {
        await queryInterface.removeIndex(
          'webhook_delivery_logs',
          'uq_webhook_delivery_logs_endpoint_event'
        );
      } catch {}
    }

    if (indexNames.includes('idx_webhook_delivery_logs_queue_schedule')) {
      try {
        await queryInterface.removeIndex(
          'webhook_delivery_logs',
          'idx_webhook_delivery_logs_queue_schedule'
        );
      } catch {}
    }

    const columns = await queryInterface
      .describeTable('webhook_delivery_logs')
      .catch(() => ({}));

    if (columns.updated_at) {
      await queryInterface.removeColumn('webhook_delivery_logs', 'updated_at');
    }

    if (columns.locked_by) {
      await queryInterface.removeColumn('webhook_delivery_logs', 'locked_by');
    }

    if (columns.locked_at) {
      await queryInterface.removeColumn('webhook_delivery_logs', 'locked_at');
    }

    if (columns.last_attempt_at) {
      await queryInterface.removeColumn('webhook_delivery_logs', 'last_attempt_at');
    }

    if (columns.next_attempt_at) {
      await queryInterface.removeColumn('webhook_delivery_logs', 'next_attempt_at');
    }
  }
};
