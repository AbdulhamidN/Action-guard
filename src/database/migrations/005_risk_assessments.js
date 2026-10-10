const { DataTypes } = require('sequelize');

module.exports = {
  up: async (queryInterface) => {
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (!tableNames.includes('risk_assessments')) {
      await queryInterface.createTable('risk_assessments', {
        id: {
          type: DataTypes.STRING(64),
          primaryKey: true,
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
        risk_score: {
          type: DataTypes.INTEGER,
          allowNull: false
        },
        risk_tier: {
          type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
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
        evaluated_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW
        }
      });
    }

    // Indexes
    const existingIndexes = await queryInterface.showIndex('risk_assessments').catch(() => []);
    const existingIndexNames = existingIndexes.map((idx) => idx.name);

    if (!existingIndexNames.includes('idx_risk_user_time')) {
      await queryInterface.addIndex('risk_assessments', ['user_id', 'evaluated_at'], {
        name: 'idx_risk_user_time'
      });
    }

    if (!existingIndexNames.includes('idx_risk_session_time')) {
      await queryInterface.addIndex('risk_assessments', ['session_id', 'evaluated_at'], {
        name: 'idx_risk_session_time'
      });
    }

    if (!existingIndexNames.includes('idx_risk_event')) {
      await queryInterface.addIndex('risk_assessments', ['event_id'], {
        name: 'idx_risk_event'
      });
    }
  },

  down: async (queryInterface) => {
    await queryInterface.dropTable('risk_assessments');
  }
};
