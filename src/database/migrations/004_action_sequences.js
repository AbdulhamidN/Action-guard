const { DataTypes } = require('sequelize');

let createdCompositeIndex = false;

module.exports = {
  up: async (queryInterface) => {
    // 1. Create action_sequences table if not exists (grouping-only schema)
    const tables = await queryInterface.showAllTables();
    const tableNames = tables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (!tableNames.includes('action_sequences')) {
      await queryInterface.createTable('action_sequences', {
        id: {
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
        started_at: {
          type: DataTypes.DATE,
          allowNull: false
        },
        last_event_at: {
          type: DataTypes.DATE,
          allowNull: false
        },
        event_count: {
          type: DataTypes.INTEGER,
          allowNull: false,
          defaultValue: 0
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
    }

    // Indexes on action_sequences
    const seqIndexes = await queryInterface.showIndex('action_sequences').catch(() => []);
    const seqIndexNames = seqIndexes.map((idx) => idx.name);

    if (!seqIndexNames.includes('idx_action_sequences_user_last_event')) {
      await queryInterface.addIndex('action_sequences', ['user_id', 'last_event_at'], {
        name: 'idx_action_sequences_user_last_event'
      });
    }

    if (!seqIndexNames.includes('idx_action_sequences_session_id')) {
      await queryInterface.addIndex('action_sequences', ['session_id'], {
        name: 'idx_action_sequences_session_id'
      });
    }

    // 2. Create sequence_events junction table if not exists
    const updatedTables = await queryInterface.showAllTables();
    const updatedTableNames = updatedTables.map((t) => (typeof t === 'string' ? t : t.tableName || Object.values(t)[0]));

    if (!updatedTableNames.includes('sequence_events')) {
      await queryInterface.createTable('sequence_events', {
        id: {
          type: DataTypes.STRING(64),
          primaryKey: true,
          allowNull: false
        },
        sequence_id: {
          type: DataTypes.STRING(64),
          allowNull: false,
          references: {
            model: 'action_sequences',
            key: 'id'
          },
          onUpdate: 'CASCADE',
          onDelete: 'CASCADE'
        },
        event_id: {
          type: DataTypes.STRING(64),
          allowNull: false,
          references: {
            model: 'security_events',
            key: 'event_id'
          },
          onUpdate: 'CASCADE',
          onDelete: 'CASCADE'
        },
        step_order: {
          type: DataTypes.INTEGER,
          allowNull: false
        },
        added_at: {
          type: DataTypes.DATE,
          allowNull: false,
          defaultValue: DataTypes.NOW
        }
      });
    }

    // Unique constraints & indexes on sequence_events
    const seqEventIndexes = await queryInterface.showIndex('sequence_events').catch(() => []);
    const seqEventIndexNames = seqEventIndexes.map((idx) => idx.name);

    if (!seqEventIndexNames.includes('uq_sequence_events_seq_event')) {
      await queryInterface.addIndex('sequence_events', ['sequence_id', 'event_id'], {
        unique: true,
        name: 'uq_sequence_events_seq_event'
      });
    }

    if (!seqEventIndexNames.includes('uq_sequence_events_seq_order')) {
      await queryInterface.addIndex('sequence_events', ['sequence_id', 'step_order'], {
        unique: true,
        name: 'uq_sequence_events_seq_order'
      });
    }

    if (!seqEventIndexNames.includes('idx_sequence_events_event_id')) {
      await queryInterface.addIndex('sequence_events', ['event_id'], {
        name: 'idx_sequence_events_event_id'
      });
    }

    // 3. Rollback-safe check for idx_security_events_user_type_time on security_events
    const existingEventsIndexes = await queryInterface.showIndex('security_events').catch(() => []);
    const existingIndexNames = existingEventsIndexes.map((idx) => idx.name);

    if (!existingIndexNames.includes('idx_security_events_user_type_time')) {
      await queryInterface.addIndex('security_events', ['user_id', 'event_type', 'timestamp'], {
        name: 'idx_security_events_user_type_time'
      });
      createdCompositeIndex = true;
    }
  },

  down: async (queryInterface) => {
    // Drop child table first
    await queryInterface.dropTable('sequence_events');
    // Drop parent table
    await queryInterface.dropTable('action_sequences');

    // Only remove idx_security_events_user_type_time if migration 004 created it
    if (createdCompositeIndex) {
      const existingEventsIndexes = await queryInterface.showIndex('security_events').catch(() => []);
      const existingIndexNames = existingEventsIndexes.map((idx) => idx.name);
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
