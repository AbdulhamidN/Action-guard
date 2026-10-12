const crypto = require('crypto');
const { DataTypes } = require('sequelize');

const DELIVERY_STATUSES = Object.freeze(['pending', 'delivered', 'failed']);

module.exports = (sequelize) => {
  const WebhookDeliveryLog = sequelize.define(
    'WebhookDeliveryLog',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `whdel_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      webhook_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'webhook_endpoints',
          key: 'id'
        },
        validate: {
          notNull: { msg: 'webhook_id is required' },
          notEmpty: { msg: 'webhook_id cannot be empty' }
        }
      },
      event_type: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'event_type is required' },
          notEmpty: { msg: 'event_type cannot be empty' }
        }
      },
      source_event_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        defaultValue: null
      },
      status: {
        type: DataTypes.ENUM(...DELIVERY_STATUSES),
        allowNull: false,
        defaultValue: 'pending',
        validate: {
          notNull: { msg: 'status is required' },
          isIn: {
            args: [DELIVERY_STATUSES],
            msg: `Invalid status. Must be one of: ${DELIVERY_STATUSES.join(', ')}`
          }
        }
      },
      attempt_count: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 1,
        validate: {
          notNull: { msg: 'attempt_count is required' },
          isInt: { msg: 'attempt_count must be an integer' },
          min: {
            args: [1],
            msg: 'attempt_count must be at least 1'
          }
        }
      },
      http_status: {
        type: DataTypes.INTEGER,
        allowNull: true,
        defaultValue: null,
        validate: {
          isInt: { msg: 'http_status must be an integer' }
        }
      },
      error_code: {
        type: DataTypes.STRING(128),
        allowNull: true,
        defaultValue: null
      },
      delivered_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null,
        validate: {
          isDate: { msg: 'delivered_at must be a valid date' }
        }
      },
      created_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'created_at is required' },
          isDate: { msg: 'created_at must be a valid date' }
        }
      }
    },
    {
      tableName: 'webhook_delivery_logs',
      timestamps: false
    }
  );

  WebhookDeliveryLog.DELIVERY_STATUSES = DELIVERY_STATUSES;

  return WebhookDeliveryLog;
};
