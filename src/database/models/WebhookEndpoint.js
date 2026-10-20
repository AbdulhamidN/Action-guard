const crypto = require('crypto');
const { DataTypes } = require('sequelize');
const { validateWebhookDestinationUrl } = require('../../utils/webhookUrlValidator');

const SUPPORTED_WEBHOOK_EVENTS = Object.freeze([
  'event.processed',
  'decision.recorded'
]);

module.exports = (sequelize) => {
  const WebhookEndpoint = sequelize.define(
    'WebhookEndpoint',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `whk_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      url: {
        type: DataTypes.STRING(512),
        allowNull: false,
        validate: {
          notNull: { msg: 'url is required' },
          notEmpty: { msg: 'url cannot be empty' },
          isHttpsUrl(value) {
            validateWebhookDestinationUrl(value);
          }
        }
      },
      subscribed_events: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: () => ['event.processed', 'decision.recorded'],
        validate: {
          notNull: { msg: 'subscribed_events is required' },
          isValidEventsArray(value) {
            if (!Array.isArray(value) || value.length === 0) {
              throw new Error('subscribed_events must be a non-empty array');
            }
            for (const evt of value) {
              if (!SUPPORTED_WEBHOOK_EVENTS.includes(evt)) {
                throw new Error(
                  `Invalid subscribed event '${evt}'. Must be one of: ${SUPPORTED_WEBHOOK_EVENTS.join(', ')}`
                );
              }
            }
          }
        }
      },
      description: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null
      },
      encrypted_secret: {
        type: DataTypes.TEXT,
        allowNull: false,
        validate: {
          notNull: { msg: 'encrypted_secret is required' },
          notEmpty: { msg: 'encrypted_secret cannot be empty' }
        }
      },
      secret_iv: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'secret_iv is required' },
          notEmpty: { msg: 'secret_iv cannot be empty' }
        }
      },
      secret_auth_tag: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'secret_auth_tag is required' },
          notEmpty: { msg: 'secret_auth_tag cannot be empty' }
        }
      },
      secret_prefix: {
        type: DataTypes.STRING(32),
        allowNull: false,
        validate: {
          notNull: { msg: 'secret_prefix is required' },
          notEmpty: { msg: 'secret_prefix cannot be empty' }
        }
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true,
        validate: {
          notNull: { msg: 'is_active is required' }
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
      },
      updated_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'updated_at is required' },
          isDate: { msg: 'updated_at must be a valid date' }
        }
      }
    },
    {
      tableName: 'webhook_endpoints',
      timestamps: false
    }
  );

  WebhookEndpoint.SUPPORTED_WEBHOOK_EVENTS = SUPPORTED_WEBHOOK_EVENTS;

  return WebhookEndpoint;
};
