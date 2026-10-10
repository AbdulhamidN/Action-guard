const { DataTypes } = require('sequelize');

/**
 * Migration 006: Increase datetime precision to milliseconds (DATETIME(3)).
 *
 * Affects:
 * - action_sequences: started_at, last_event_at
 * - sequence_events: added_at
 * - risk_assessments: evaluated_at
 * - security_events: timestamp
 */
module.exports = {
  up: async (queryInterface) => {
    // 1. action_sequences
    await queryInterface.changeColumn('action_sequences', 'started_at', {
      type: DataTypes.DATE(3),
      allowNull: false
    });
    await queryInterface.changeColumn('action_sequences', 'last_event_at', {
      type: DataTypes.DATE(3),
      allowNull: false
    });

    // 2. sequence_events
    await queryInterface.changeColumn('sequence_events', 'added_at', {
      type: DataTypes.DATE(3),
      allowNull: false,
      defaultValue: DataTypes.NOW
    });

    // 3. risk_assessments
    await queryInterface.changeColumn('risk_assessments', 'evaluated_at', {
      type: DataTypes.DATE(3),
      allowNull: false,
      defaultValue: DataTypes.NOW
    });

    // 4. security_events
    await queryInterface.changeColumn('security_events', 'timestamp', {
      type: DataTypes.DATE(3),
      allowNull: false,
      defaultValue: DataTypes.NOW
    });
  },

  down: async (queryInterface) => {
    // 1. action_sequences
    await queryInterface.changeColumn('action_sequences', 'started_at', {
      type: DataTypes.DATE,
      allowNull: false
    });
    await queryInterface.changeColumn('action_sequences', 'last_event_at', {
      type: DataTypes.DATE,
      allowNull: false
    });

    // 2. sequence_events
    await queryInterface.changeColumn('sequence_events', 'added_at', {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    });

    // 3. risk_assessments
    await queryInterface.changeColumn('risk_assessments', 'evaluated_at', {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    });

    // 4. security_events
    await queryInterface.changeColumn('security_events', 'timestamp', {
      type: DataTypes.DATE,
      allowNull: false,
      defaultValue: DataTypes.NOW
    });
  }
};
