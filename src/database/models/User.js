const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const User = sequelize.define(
    'User',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true,
        validate: {
          notEmpty: true,
          isEmail: true
        }
      },
      password_hash: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: {
          notEmpty: true
        }
      },
      recovery_email: {
        type: DataTypes.STRING(255),
        allowNull: true,
        defaultValue: null,
        validate: {
          isEmail: true
        }
      },
      phone_number: {
        type: DataTypes.STRING(32),
        allowNull: true,
        defaultValue: null
      },
      mfa_enabled: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      locked_until: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
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
      tableName: 'users',
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at'
    }
  );

  return User;
};
