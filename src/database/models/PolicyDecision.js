const crypto = require('crypto');
const { DataTypes } = require('sequelize');

const ACTION_SENSITIVITIES = ['low', 'medium', 'high', 'critical'];
const RISK_TIERS = ['low', 'medium', 'high', 'critical'];
const DECISIONS = ['allow', 'monitor', 'reverify', 'delay', 'block'];
const ENFORCEMENT_OUTCOMES = [
  'allowed',
  'monitored',
  'elevated_allowed',
  'recommend_only_allowed',
  'step_up_challenged',
  'delayed',
  'blocked',
  'contained_and_blocked',
  'fail_safe_challenged',
  'fail_safe_blocked'
];
const ENFORCEMENT_MODES = ['automatic', 'recommend_only'];

module.exports = (sequelize) => {
  const PolicyDecision = sequelize.define(
    'PolicyDecision',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `dec_${crypto.randomUUID()}`,
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
      event_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        references: {
          model: 'security_events',
          key: 'event_id'
        }
      },
      risk_assessment_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        defaultValue: null
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
      action_type: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'action_type is required' },
          notEmpty: { msg: 'action_type cannot be empty' }
        }
      },
      action_sensitivity: {
        type: DataTypes.ENUM(...ACTION_SENSITIVITIES),
        allowNull: false,
        validate: {
          notNull: { msg: 'action_sensitivity is required' },
          isIn: {
            args: [ACTION_SENSITIVITIES],
            msg: `Invalid action_sensitivity. Must be one of: ${ACTION_SENSITIVITIES.join(', ')}`
          }
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
      recommended_decision: {
        type: DataTypes.ENUM(...DECISIONS),
        allowNull: false,
        validate: {
          notNull: { msg: 'recommended_decision is required' },
          isIn: {
            args: [DECISIONS],
            msg: `Invalid recommended_decision. Must be one of: ${DECISIONS.join(', ')}`
          }
        }
      },
      effective_decision: {
        type: DataTypes.ENUM(...DECISIONS),
        allowNull: false,
        validate: {
          notNull: { msg: 'effective_decision is required' },
          isIn: {
            args: [DECISIONS],
            msg: `Invalid effective_decision. Must be one of: ${DECISIONS.join(', ')}`
          }
        }
      },
      enforcement_outcome: {
        type: DataTypes.ENUM(...ENFORCEMENT_OUTCOMES),
        allowNull: false,
        validate: {
          notNull: { msg: 'enforcement_outcome is required' },
          isIn: {
            args: [ENFORCEMENT_OUTCOMES],
            msg: `Invalid enforcement_outcome. Must be one of: ${ENFORCEMENT_OUTCOMES.join(', ')}`
          }
        }
      },
      enforcement_mode: {
        type: DataTypes.ENUM(...ENFORCEMENT_MODES),
        allowNull: false,
        validate: {
          notNull: { msg: 'enforcement_mode is required' },
          isIn: {
            args: [ENFORCEMENT_MODES],
            msg: `Invalid enforcement_mode. Must be one of: ${ENFORCEMENT_MODES.join(', ')}`
          }
        }
      },
      policy_version: {
        type: DataTypes.STRING(64),
        allowNull: false,
        validate: {
          notNull: { msg: 'policy_version is required' },
          notEmpty: { msg: 'policy_version cannot be empty' }
        }
      },
      reasons: {
        type: DataTypes.JSON,
        allowNull: false,
        defaultValue: []
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
      decided_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW,
        validate: {
          notNull: { msg: 'decided_at is required' },
          isDate: { msg: 'decided_at must be a valid date' }
        }
      }
    },
    {
      tableName: 'policy_decisions',
      timestamps: false
    }
  );

  PolicyDecision.ACTION_SENSITIVITIES = ACTION_SENSITIVITIES;
  PolicyDecision.RISK_TIERS = RISK_TIERS;
  PolicyDecision.DECISIONS = DECISIONS;
  PolicyDecision.ENFORCEMENT_OUTCOMES = ENFORCEMENT_OUTCOMES;
  PolicyDecision.ENFORCEMENT_MODES = ENFORCEMENT_MODES;

  return PolicyDecision;
};
