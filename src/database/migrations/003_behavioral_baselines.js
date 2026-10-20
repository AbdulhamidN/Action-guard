const { DataTypes } = require('sequelize');

let createdCompositeIndex = false;

module.exports = {
  up: async (queryInterface) => {
    await queryInterface.createTable('behavioral_baselines', {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false
      },
      user_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true,
        references: {
          model: 'users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      total_logins: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0
      },
      has_sufficient_history: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      login_hours: {
        type: DataTypes.JSON,
        allowNull: true
      },
      typical_devices: {
        type: DataTypes.JSON,
        allowNull: true
      },
      typical_countries: {
        type: DataTypes.JSON,
        allowNull: true
      },
      last_calculated_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      created_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      updated_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      }
    });

    // Idempotently create composite index on security_events if missing
    const existingIndexes = await queryInterface.showIndex('security_events').catch(() => []);
    const existingIndexNames = existingIndexes.map((idx) => idx.name);

    if (!existingIndexNames.includes('idx_security_events_user_type_time')) {
      await queryInterface.addIndex('security_events', ['user_id', 'event_type', 'timestamp'], {
        name: 'idx_security_events_user_type_time'
      });
      createdCompositeIndex = true;
    }
  },

  down: async (queryInterface) => {
    await queryInterface.dropTable('behavioral_baselines');

    if (createdCompositeIndex) {
      const existingIndexes = await queryInterface.showIndex('security_events').catch(() => []);
      const existingIndexNames = existingIndexes.map((idx) => idx.name);
      if (existingIndexNames.includes('idx_security_events_user_type_time')) {
        await queryInterface.removeIndex('security_events', 'idx_security_events_user_type_time');
      }
      createdCompositeIndex = false;
    }
  },

  wasCompositeIndexCreated: () => createdCompositeIndex,
  resetCompositeIndexState: () => {
    createdCompositeIndex = false;
  }
};
