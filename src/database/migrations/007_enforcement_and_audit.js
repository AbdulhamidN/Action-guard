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
const ELEVATION_AUDIT_ACTIONS = ['granted', 'used', 'revoked', 'expired'];

/**
 * Migration 007: Enforcement Layer (PEP) & Audit Tables
 *
 * 1. Adds recovery_email, phone_number, mfa_enabled, and locked_until to users.
 * 2. Creates policy_decisions table for durable PEP decision audit logs.
 * 3. Creates elevation_audit_logs table for step-up elevation lifecycle audit logs.
 */
module.exports = {
  up: async (queryInterface) => {
    // 1. Add columns to users table idempotently
    const userColumns = await queryInterface.describeTable('users');

    if (!userColumns.recovery_email) {
      await queryInterface.addColumn('users', 'recovery_email', {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!userColumns.phone_number) {
      await queryInterface.addColumn('users', 'phone_number', {
        type: DataTypes.STRING(32),
        allowNull: true,
        defaultValue: null
      });
    }

    if (!userColumns.mfa_enabled) {
      await queryInterface.addColumn('users', 'mfa_enabled', {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
      });
    }

    if (!userColumns.locked_until) {
      await queryInterface.addColumn('users', 'locked_until', {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      });
    }

    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    // 2. policy_decisions table
    if (!tableNames.includes('policy_decisions')) {
      await queryInterface.createTable('policy_decisions', {
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
        event_id: {
          type: DataTypes.STRING(64),
          allowNull: true,
          references: {
            model: 'security_events',
            key: 'event_id'
          },
          onUpdate: 'CASCADE',
          onDelete: 'SET NULL'
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
          onUpdate: 'CASCADE',
          onDelete: 'CASCADE'
        },
        session_id: {
          type: DataTypes.STRING(64),
          allowNull: true,
          references: {
            model: 'sessions',
            key: 'id'
          },
          onUpdate: 'CASCADE',
          onDelete: 'SET NULL'
        },
        action_type: {
          type: DataTypes.STRING(64),
          allowNull: false
        },
        action_sensitivity: {
          type: DataTypes.ENUM(...ACTION_SENSITIVITIES),
          allowNull: false
        },
        risk_score: {
          type: DataTypes.INTEGER,
          allowNull: false
        },
        risk_tier: {
          type: DataTypes.ENUM(...RISK_TIERS),
          allowNull: false
        },
        recommended_decision: {
          type: DataTypes.ENUM(...DECISIONS),
          allowNull: false
        },
        effective_decision: {
          type: DataTypes.ENUM(...DECISIONS),
          allowNull: false
        },
        enforcement_outcome: {
          type: DataTypes.ENUM(...ENFORCEMENT_OUTCOMES),
          allowNull: false
        },
        enforcement_mode: {
          type: DataTypes.ENUM(...ENFORCEMENT_MODES),
          allowNull: false
        },
        policy_version: {
          type: DataTypes.STRING(64),
          allowNull: false
        },
        reasons: {
          type: DataTypes.JSON,
          allowNull: false
        },
        contributing_signals: {
          type: DataTypes.JSON,
          allowNull: false
        },
        explanation: {
          type: DataTypes.JSON,
          allowNull: false
        },
        decided_at: {
          type: DataTypes.DATE(3),
          allowNull: false,
          defaultValue: DataTypes.NOW
        }
      });
    }

    const existingDecisionIndexes = await queryInterface.showIndex('policy_decisions').catch(() => []);
    const decisionIndexNames = existingDecisionIndexes.map((idx) => idx.name);

    if (!decisionIndexNames.includes('idx_policy_decisions_user_time')) {
      await queryInterface.addIndex('policy_decisions', ['user_id', 'decided_at'], {
        name: 'idx_policy_decisions_user_time'
      });
    }

    if (!decisionIndexNames.includes('idx_policy_decisions_session_time')) {
      await queryInterface.addIndex('policy_decisions', ['session_id', 'decided_at'], {
        name: 'idx_policy_decisions_session_time'
      });
    }

    if (!decisionIndexNames.includes('idx_policy_decisions_event')) {
      await queryInterface.addIndex('policy_decisions', ['event_id'], {
        name: 'idx_policy_decisions_event'
      });
    }

    if (!decisionIndexNames.includes('idx_policy_decisions_assessment')) {
      await queryInterface.addIndex('policy_decisions', ['risk_assessment_id'], {
        name: 'idx_policy_decisions_assessment'
      });
    }

    // 3. elevation_audit_logs table
    if (!tableNames.includes('elevation_audit_logs')) {
      await queryInterface.createTable('elevation_audit_logs', {
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
          },
          onUpdate: 'CASCADE',
          onDelete: 'CASCADE'
        },
        session_id: {
          type: DataTypes.STRING(64),
          allowNull: true,
          references: {
            model: 'sessions',
            key: 'id'
          },
          onUpdate: 'CASCADE',
          onDelete: 'SET NULL'
        },
        scope: {
          type: DataTypes.STRING(64),
          allowNull: false
        },
        event_action: {
          type: DataTypes.ENUM(...ELEVATION_AUDIT_ACTIONS),
          allowNull: false
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
          defaultValue: DataTypes.NOW
        }
      });
    }

    const existingElevationIndexes = await queryInterface.showIndex('elevation_audit_logs').catch(() => []);
    const elevationIndexNames = existingElevationIndexes.map((idx) => idx.name);

    if (!elevationIndexNames.includes('idx_elevation_audit_session_time')) {
      await queryInterface.addIndex('elevation_audit_logs', ['session_id', 'recorded_at'], {
        name: 'idx_elevation_audit_session_time'
      });
    }

    if (!elevationIndexNames.includes('idx_elevation_audit_user_time')) {
      await queryInterface.addIndex('elevation_audit_logs', ['user_id', 'recorded_at'], {
        name: 'idx_elevation_audit_user_time'
      });
    }
  },

  down: async (queryInterface) => {
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (tableNames.includes('elevation_audit_logs')) {
      await queryInterface.dropTable('elevation_audit_logs');
    }
    if (tableNames.includes('policy_decisions')) {
      await queryInterface.dropTable('policy_decisions');
    }

    const userColumns = await queryInterface.describeTable('users').catch(() => ({}));
    if (userColumns.locked_until) {
      await queryInterface.removeColumn('users', 'locked_until');
    }
    if (userColumns.mfa_enabled) {
      await queryInterface.removeColumn('users', 'mfa_enabled');
    }
    if (userColumns.phone_number) {
      await queryInterface.removeColumn('users', 'phone_number');
    }
    if (userColumns.recovery_email) {
      await queryInterface.removeColumn('users', 'recovery_email');
    }
  }
};
