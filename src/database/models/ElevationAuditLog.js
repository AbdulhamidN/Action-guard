const crypto = require('crypto');
const { DataTypes } = require('sequelize');

const ELEVATION_AUDIT_ACTIONS = ['granted', 'used', 'revoked', 'expired'];
const RISK_TIERS = ['low', 'medium', 'high', 'critical'];

module.exports = (sequelize) => {
  const ElevationAuditLog = sequelize.define(
    'ElevationAuditLog',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `elv_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      seq_no: {
        type: DataTypes.BIGINT.UNSIGNED,
        autoIncrement: true,
        unique: true,
        allowNull: true
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
      scope: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'scope is required' },
          notEmpty: { msg: 'scope cannot be empty' }
        }
      },
      event_action: {
        type: DataTypes.ENUM(...ELEVATION_AUDIT_ACTIONS),
        allowNull: false,
        validate: {
          notNull: { msg: 'event_action is required' },
          isIn: {
            args: [ELEVATION_AUDIT_ACTIONS],
            msg: `Invalid event_action. Must be one of: ${ELEVATION_AUDIT_ACTIONS.join(', ')}`
          }
        }
      },
      reason: {
        type: DataTypes.STRING(128),
        allowNull: true,
        defaultValue: null
      },
      jti: {
        type: DataTypes.STRING(128),
        allowNull: true,
        defaultValue: null
      },
      granted_at_risk_tier: {
        type: DataTypes.ENUM(...RISK_TIERS),
        allowNull: true,
        defaultValue: null
      },
      expires_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      },
      metadata: {
        type: DataTypes.JSON,
        allowNull: true,
        defaultValue: null
      },
      recorded_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'recorded_at is required' },
          isDate: { msg: 'recorded_at must be a valid date' }
        }
      }
    },
    {
      tableName: 'elevation_audit_logs',
      timestamps: false
    }
  );

  ElevationAuditLog.ELEVATION_AUDIT_ACTIONS = ELEVATION_AUDIT_ACTIONS;
  ElevationAuditLog.RISK_TIERS = RISK_TIERS;

  return ElevationAuditLog;
};
