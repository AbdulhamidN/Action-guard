const { DataTypes } = require('sequelize');

module.exports = (sequelize) => {
  const Device = sequelize.define(
    'Device',
    {
      id: {
        type: DataTypes.STRING(64),
        primaryKey: true,
        defaultValue: DataTypes.UUIDV4,
        allowNull: false
      },
      user_id: {
        type: DataTypes.STRING(64),
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        validate: {
          notEmpty: true
        }
      },
      fingerprint: {
        type: DataTypes.STRING(255),
        allowNull: false,
        validate: {
          notEmpty: true
        }
      },
      is_trusted: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      first_seen_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      }
    },
    {
      tableName: 'devices',
      timestamps: false
    }
  );

  return Device;
};
