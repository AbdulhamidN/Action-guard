const sequelize = require('../index');
const initUserModel = require('./User');
const initSessionModel = require('./Session');
const initDeviceModel = require('./Device');

const User = initUserModel(sequelize);
const Session = initSessionModel(sequelize);
const Device = initDeviceModel(sequelize);

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

module.exports = {
  sequelize,
  User,
  Session,
  Device
};
