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

module.exports = {
  up: async (queryInterface) => {
    await queryInterface.createTable('security_events', {
      event_id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
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
      event_type: {
        type: DataTypes.ENUM(...SUPPORTED_EVENT_TYPES),
        allowNull: false
      },
      timestamp: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      context: {
        type: DataTypes.JSON,
        allowNull: true
      },
      metadata: {
        type: DataTypes.JSON,
        allowNull: true
      }
    });

    // Idempotently create indexes to avoid duplicate key errors on repeated test runs
    const existingIndexes = await queryInterface.showIndex('security_events').catch(() => []);
    const existingIndexNames = existingIndexes.map((idx) => idx.name);

    if (!existingIndexNames.includes('idx_security_events_user_id')) {
      await queryInterface.addIndex('security_events', ['user_id'], {
        name: 'idx_security_events_user_id'
      });
    }

    if (!existingIndexNames.includes('idx_security_events_session_id')) {
      await queryInterface.addIndex('security_events', ['session_id'], {
        name: 'idx_security_events_session_id'
      });
    }

    if (!existingIndexNames.includes('idx_security_events_event_type')) {
      await queryInterface.addIndex('security_events', ['event_type'], {
        name: 'idx_security_events_event_type'
      });
    }

    if (!existingIndexNames.includes('idx_security_events_timestamp')) {
      await queryInterface.addIndex('security_events', ['timestamp'], {
        name: 'idx_security_events_timestamp'
      });
    }

    if (!existingIndexNames.includes('idx_security_events_user_time')) {
      await queryInterface.addIndex('security_events', ['user_id', 'timestamp'], {
        name: 'idx_security_events_user_time'
      });
    }
  },

  down: async (queryInterface) => {
    await queryInterface.dropTable('security_events');
  }
};
