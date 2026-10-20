const crypto = require('crypto');
const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const BehavioralBaseline = sequelize.define(
    'BehavioralBaseline',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        allowNull: false,
        defaultValue: () => `base_${crypto.randomUUID()}`,
        validate: {
          notNull: { msg: 'id is required' },
          notEmpty: { msg: 'id cannot be empty' }
        }
      },
      user_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        unique: true,
        references: {
          model: 'users',
          key: 'id'
        },
        validate: {
          notNull: { msg: 'user_id is required' },
          notEmpty: { msg: 'user_id cannot be empty' }
        }
      },
      total_logins: {
        type: DataTypes.INTEGER,
        allowNull: false,
        defaultValue: 0,
        validate: {
          isInt: true,
          min: 0
        }
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
        allowNull: true,
        defaultValue: []
      },
      typical_countries: {
        type: DataTypes.JSON,
        allowNull: true,
        defaultValue: []
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
    },
    {
      tableName: 'behavioral_baselines',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    }
  );

  return BehavioralBaseline;
};
