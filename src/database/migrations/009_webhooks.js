const { DataTypes } = require('sequelize');

const DELIVERY_STATUSES = ['pending', 'delivered', 'failed'];

/**
 * Migration: 009_webhooks
 *
 * Implements the database persistence schema for Module 11.2:
 * Outbound Webhook Endpoints and Delivery Audit Logs.
 *
 * Creates the `webhook_endpoints` and `webhook_delivery_logs` tables
 * with foreign key constraints and indexes.
 */
module.exports = {
  up: async (queryInterface) => {
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) =>
      typeof t === 'string' ? t : t.tableName || Object.values(t)[0]
    );

    if (!tableNames.includes('webhook_endpoints')) {
      await queryInterface.createTable(
        'webhook_endpoints',
        {
          id: {
            type: DataTypes.STRING(64),
            primaryKey: true,
            allowNull: false
          },
          url: {
            type: DataTypes.STRING(512),
            allowNull: false
          },
          subscribed_events: {
            type: DataTypes.JSON,
            allowNull: false
          },
          description: {
            type: DataTypes.STRING(255),
            allowNull: true,
            defaultValue: null
          },
          encrypted_secret: {
            type: DataTypes.TEXT,
            allowNull: false
          },
          secret_iv: {
            type: DataTypes.STRING(64),
            allowNull: false
          },
          secret_auth_tag: {
            type: DataTypes.STRING(64),
            allowNull: false
          },
          secret_prefix: {
            type: DataTypes.STRING(32),
            allowNull: false
          },
          is_active: {
            type: DataTypes.BOOLEAN,
            allowNull: false,
            defaultValue: true
          },
          created_at: {
            type: DataTypes.DATE(3),
            allowNull: false,
            defaultValue: DataTypes.NOW
          },
          updated_at: {
            type: DataTypes.DATE(3),
            allowNull: false,
            defaultValue: DataTypes.NOW
          }
        },
        {
          charset: 'utf8mb4',
          collate: 'utf8mb4_unicode_ci'
        }
      );
    }

    try {
      await queryInterface.addIndex('webhook_endpoints', ['is_active'], {
        name: 'idx_webhook_endpoints_is_active'
      });
    } catch {}

    if (!tableNames.includes('webhook_delivery_logs')) {
      await queryInterface.createTable(
        'webhook_delivery_logs',
        {
          id: {
            type: DataTypes.STRING(64),
            primaryKey: true,
            allowNull: false
          },
          webhook_id: {
            type: DataTypes.STRING(64),
            allowNull: false,
            references: {
              model: 'webhook_endpoints',
              key: 'id'
            },
            onUpdate: 'CASCADE',
            onDelete: 'CASCADE'
          },
          event_type: {
            type: DataTypes.STRING(64),
            allowNull: false
          },
          source_event_id: {
            type: DataTypes.STRING(64),
            allowNull: true,
            defaultValue: null
          },
          status: {
            type: DataTypes.ENUM(...DELIVERY_STATUSES),
            allowNull: false,
            defaultValue: 'pending'
          },
          attempt_count: {
            type: DataTypes.INTEGER,
            allowNull: false,
            defaultValue: 1
          },
          http_status: {
            type: DataTypes.INTEGER,
            allowNull: true,
            defaultValue: null
          },
          error_code: {
            type: DataTypes.STRING(128),
            allowNull: true,
            defaultValue: null
          },
          delivered_at: {
            type: DataTypes.DATE(3),
            allowNull: true,
            defaultValue: null
          },
          created_at: {
            type: DataTypes.DATE(3),
            allowNull: false,
            defaultValue: DataTypes.NOW
          }
        },
        {
          charset: 'utf8mb4',
          collate: 'utf8mb4_unicode_ci'
        }
      );
    }

    try {
      await queryInterface.addIndex('webhook_delivery_logs', ['webhook_id'], {
        name: 'idx_webhook_delivery_logs_webhook_id'
      });
    } catch {}

    try {
      await queryInterface.addIndex('webhook_delivery_logs', ['status'], {
        name: 'idx_webhook_delivery_logs_status'
      });
    } catch {}

    try {
      await queryInterface.addIndex('webhook_delivery_logs', ['source_event_id'], {
        name: 'idx_webhook_delivery_logs_source_event'
      });
    } catch {}
  },

  down: async (queryInterface) => {
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) =>
      typeof t === 'string' ? t : t.tableName || Object.values(t)[0]
    );

    if (tableNames.includes('webhook_delivery_logs')) {
      await queryInterface.dropTable('webhook_delivery_logs');
    }

    if (tableNames.includes('webhook_endpoints')) {
      await queryInterface.dropTable('webhook_endpoints');
    }
  }
};
