const crypto = require('crypto');
const { DataTypes } = require('sequelize');

const RISK_TIERS = ['low', 'medium', 'high', 'critical'];

module.exports = (sequelize) => {
  const RiskAssessment = sequelize.define(
    'RiskAssessment',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `rsk_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      event_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        references: {
          model: 'security_events',
          key: 'event_id'
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
      risk_score: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          notNull: { msg: 'risk_score is required' },
          isInt: { msg: 'risk_score must be an integer' },
          min: { args: [0], msg: 'risk_score must be between 0 and 100' },
          max: { args: [100], msg: 'risk_score must be between 0 and 100' }
        }
      },
      risk_tier: {
        type: DataTypes.ENUM(...RISK_TIERS),
        allowNull: false,
        validate: {
          notNull: { msg: 'risk_tier is required' },
          isIn: {
            args: [RISK_TIERS],
            msg: `Invalid risk_tier. Must be one of: ${RISK_TIERS.join(', ')}`
          }
        }
      },
      contributing_signals: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: []
      },
      explanation: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: {}
      },
      evaluated_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'evaluated_at is required' },
          isDate: { msg: 'evaluated_at must be a valid date' }
        }
      }
    },
    {
      tableName: 'risk_assessments',
      timestamps: false
    }
  );

  RiskAssessment.RISK_TIERS = RISK_TIERS;

  return RiskAssessment;
};
