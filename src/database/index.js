const { Sequelize } = require('sequelize');

const isDocker = process.env.DB_HOST === 'mysql';
const defaultPort = isDocker ? 3306 : 3307;

const sequelize = new Sequelize(
  process.env.DB_NAME || 'actionguard',
  process.env.DB_USER || 'actionguard',
  process.env.DB_PASSWORD !== undefined ? process.env.DB_PASSWORD : 'actionguard_secret',
  {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || defaultPort, 10),
    dialect: 'mysql',
    logging: process.env.DB_LOGGING === 'true' ? console.log : false,
    pool: {
      max: 10,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  }
);

module.exports = sequelize;
