const crypto = require('crypto');
const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const SequenceEvent = sequelize.define(
    'SequenceEvent',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `seq_evt_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      sequence_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'action_sequences',
          key: 'id'
        },
        validate: {
          notNull: { msg: 'sequence_id is required' },
          notEmpty: { msg: 'sequence_id cannot be empty' }
        }
      },
      event_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'security_events',
          key: 'event_id'
        },
        validate: {
          notNull: { msg: 'event_id is required' },
          notEmpty: { msg: 'event_id cannot be empty' }
        }
      },
      step_order: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
          isInt: true,
          min: 1
        }
      },
      added_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      }
    },
    {
      tableName: 'sequence_events',
      timestamps: false
    }
  );

  return SequenceEvent;
};
