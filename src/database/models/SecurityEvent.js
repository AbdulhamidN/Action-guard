const crypto = require('crypto');
const { DataTypes } = require('sequelize');

const SUPPORTED_EVENT_TYPES = [
  'login_success',
  'login_failed',
  'new_device',
  'password_change',
  'password_reset',
  'recovery_email_change',
  'phone_number_change',
  'mfa_change',
  'session_created',
  'session_terminated',
  'high_impact_action',
  'verification_success',
  'verification_failed'
];

const ACTION_SENSITIVITY_LEVELS = [
  'low',
  'medium',
  'high',
  'critical'
];

module.exports = (sequelize) => {
  const SecurityEvent = sequelize.define(
    'SecurityEvent',
    {
      event_id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `evt_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'event_id is required' },
          notEmpty: { msg: 'event_id cannot be empty' }
        }
      },
      user_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        validate: {
          notNull: { msg: 'user_id is required' },
          notEmpty: { msg: 'user_id cannot be empty' }
        }
      },
      session_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        references: {
          model: 'sessions',
          key: 'id'
        }
      },
      event_type: {
        type: DataTypes.ENUM(...SUPPORTED_EVENT_TYPES),
        allowNull: false,
        validate: {
          notNull: { msg: 'event_type is required' },
          notEmpty: { msg: 'event_type cannot be empty' },
          isIn: {
            args: [SUPPORTED_EVENT_TYPES],
            msg: `Invalid event_type. Must be one of: ${SUPPORTED_EVENT_TYPES.join(', ')}`
          }
        }
      },
      timestamp: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'timestamp is required' },
          isDate: { msg: 'timestamp must be a valid date' }
        }
      },
      context: {
        type: DataTypes.JSON,
        allowNull: true,
        defaultValue: {}
      },
      metadata: {
        type: DataTypes.JSON,
        allowNull: true,
        defaultValue: {},
        validate: {
          isValidMetadata(value) {
            if (value && typeof value === 'object') {
              if (value.action_sensitivity !== undefined && value.action_sensitivity !== null) {
                if (!ACTION_SENSITIVITY_LEVELS.includes(value.action_sensitivity)) {
                  throw new Error(
                    `Invalid action_sensitivity: '${value.action_sensitivity}'. Must be one of: ${ACTION_SENSITIVITY_LEVELS.join(', ')}`
                  );
                }
              }
            }
          }
        }
      }
    },
    {
      tableName: 'security_events',
      timestamps: false
    }
  );

  SecurityEvent.SUPPORTED_EVENT_TYPES = SUPPORTED_EVENT_TYPES;
  SecurityEvent.ACTION_SENSITIVITY_LEVELS = ACTION_SENSITIVITY_LEVELS;

  return SecurityEvent;
};
