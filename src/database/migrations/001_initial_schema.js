const { DataTypes } = require('sequelize');

module.exports = {
  up: async (queryInterface) => {
    // 1. users table
    await queryInterface.createTable('users', {
      id: {
        type: DataTypes.STRING(36),
        primaryKey: true,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING(255),
        allowNull: false,
        unique: true
      },
      password_hash: {
        type: DataTypes.STRING(255),
        allowNull: false
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

    // 2. sessions table
    await queryInterface.createTable('sessions', {
      id: {
        type: DataTypes.STRING(36),
        primaryKey: true,
        allowNull: false
      },
      user_id: {
        type: DataTypes.STRING(36),
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      created_at: {
        type: DataTypes.DATE,
        allowNull: false,
        defaultValue: DataTypes.NOW
      },
      expires_at: {
        type: DataTypes.DATE,
        allowNull: false
      },
      is_active: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
      }
    });

    // 3. devices table
    await queryInterface.createTable('devices', {
      id: {
        type: DataTypes.STRING(36),
        primaryKey: true,
        allowNull: false
      },
      user_id: {
        type: DataTypes.STRING(36),
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE'
      },
      fingerprint: {
        type: DataTypes.STRING(255),
        allowNull: false
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
    });
  },

  down: async (queryInterface) => {
    await queryInterface.dropTable('devices');
    await queryInterface.dropTable('sessions');
    await queryInterface.dropTable('users');
  }
};
