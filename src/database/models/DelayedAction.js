'use strict';

const { DataTypes } = require('sequelize');

const ACTION_SENSITIVITIES = ['low', 'medium', 'high', 'critical'];
const RISK_TIERS = ['low', 'medium', 'high', 'critical'];
const DELAYED_ACTION_STATUSES = [
  'pending',
  'executing',
  'completed',
  'cancelled',
  'expired',
  'rejected',
  'failed'
];

module.exports = (sequelize) => {
  const DelayedAction = sequelize.define(
    'DelayedAction',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false
      },
      seq_no: {
        type: DataTypes.BIGINT.UNSIGNED,
        autoIncrement: true,
        unique: true,
        allowNull: false
      },
      user_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
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
      decision_id: {
        type: DataTypes.STRING(64),
        allowNull: true,
        references: {
          model: 'policy_decisions',
          key: 'id'
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
      action_type: {
        type: DataTypes.STRING(64),
        allowNull: false
      },
      action_sensitivity: {
        type: DataTypes.ENUM(...ACTION_SENSITIVITIES),
        allowNull: false
      },
      route_path: {
        type: DataTypes.STRING(255),
        allowNull: false
      },
      route_method: {
        type: DataTypes.STRING(16),
        allowNull: false,
        defaultValue: 'POST'
      },
      action_payload: {
        type: DataTypes.JSON,
        allowNull: false
      },
      request_context: {
        type: DataTypes.JSON,
        allowNull: true
      },
      scheduled_at_risk_tier: {
        type: DataTypes.ENUM(...RISK_TIERS),
        allowNull: false
      },
      cooling_off_seconds: {
        type: DataTypes.INTEGER,
        allowNull: false
      },
      status: {
        type: DataTypes.ENUM(...DELAYED_ACTION_STATUSES),
        allowNull: false,
        defaultValue: 'pending'
      },
      cancellation_token_hash: {
        type: DataTypes.STRING(64),
        allowNull: false
      },
      scheduled_at: {
        type: DataTypes.DATE(3),
        allowNull: false
      },
      execute_at: {
        type: DataTypes.DATE(3),
        allowNull: false
      },
      expires_at: {
        type: DataTypes.DATE(3),
        allowNull: false
      },
      cancelled_at: {
        type: DataTypes.DATE(3),
        allowNull: true
      },
      cancelled_by: {
        type: DataTypes.STRING(64),
        allowNull: true
      },
      cancellation_reason: {
        type: DataTypes.STRING(255),
        allowNull: true
      },
      executed_at: {
        type: DataTypes.DATE(3),
        allowNull: true
      },
      execution_result: {
        type: DataTypes.JSON,
        allowNull: true
      },
      failure_reason: {
        type: DataTypes.TEXT,
        allowNull: true
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
      tableName: 'delayed_actions',
      timestamps: false,
      indexes: [
        {
          name: 'idx_delayed_actions_user',
          fields: ['user_id']
        },
        {
          name: 'idx_delayed_actions_status_execute',
          fields: ['status', 'execute_at']
        },
        {
          name: 'idx_delayed_actions_token_hash',
          fields: ['cancellation_token_hash']
        },
        {
          name: 'idx_delayed_actions_session',
          fields: ['session_id']
        }
      ]
    }
  );

  return DelayedAction;
};
