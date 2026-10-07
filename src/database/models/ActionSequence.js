const crypto = require('crypto');
const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const ActionSequence = sequelize.define(
    'ActionSequence',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `seq_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
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
      started_at: {
        type: DataTypes.DATE,
        allowNull: false,
        validate: {
          notNull: { msg: 'started_at is required' },
          isDate: { msg: 'started_at must be a valid date' }
        }
      },
      last_event_at: {
        type: DataTypes.DATE,
        allowNull: false,
        validate: {
          notNull: { msg: 'last_event_at is required' },
          isDate: { msg: 'last_event_at must be a valid date' }
        }
      },
      event_count: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
        validate: {
          isInt: true,
          min: 0
        }
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
    },
    {
      tableName: 'action_sequences',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    }
  );

  return ActionSequence;
};
