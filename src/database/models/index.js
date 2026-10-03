const sequelize = require('../index');
const initUserModel = require('./User');
const initSessionModel = require('./Session');
const initDeviceModel = require('./Device');
const initSecurityEventModel = require('./SecurityEvent');

const User = initUserModel(sequelize);
const Session = initSessionModel(sequelize);
const Device = initDeviceModel(sequelize);
const SecurityEvent = initSecurityEventModel(sequelize);

// Associations
User.hasMany(Session, {
  foreignKey: 'user_id',
  as: 'sessions',
  onDelete: 'CASCADE'
});
Session.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

User.hasMany(Device, {
  foreignKey: 'user_id',
  as: 'devices',
  onDelete: 'CASCADE'
});
Device.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

User.hasMany(SecurityEvent, {
  foreignKey: 'user_id',
  as: 'securityEvents',
  onDelete: 'CASCADE'
});
SecurityEvent.belongsTo(User, {
  foreignKey: 'user_id',
  as: 'user'
});

Session.hasMany(SecurityEvent, {
  foreignKey: 'session_id',
  as: 'securityEvents',
  onDelete: 'SET NULL'
});
SecurityEvent.belongsTo(Session, {
  foreignKey: 'session_id',
  as: 'session'
});

module.exports = {
  sequelize,
  User,
  Session,
  Device,
  SecurityEvent
};
