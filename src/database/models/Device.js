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
      label: {
        type: DataTypes.STRING(100),
        allowNull: true,
        defaultValue: null,
        validate: {
          len: [0, 100]
        }
      },
      is_trusted: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false
      },
      trusted_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      },
      expires_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      },
      revoked_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      },
      first_seen_at: {
        type: DataTypes.DATE(3),
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      last_used_at: {
        type: DataTypes.DATE(3),
        allowNull: true,
        defaultValue: null
      }
    },
    {
      tableName: 'devices',
      timestamps: false,
      indexes: [
        {
          name: 'idx_devices_user_fingerprint',
          unique: true,
          fields: ['user_id', 'fingerprint']
        },
        {
          name: 'idx_devices_user_trusted',
          fields: ['user_id', 'is_trusted', 'expires_at']
        },
        {
          name: 'idx_devices_user_last_used',
          fields: ['user_id', 'last_used_at']
        }
      ]
    }
  );

  Device.prototype.toJSON = function () {
    const values = Object.assign({}, this.get());
    delete values.fingerprint;
    return values;
  };

  return Device;
};
