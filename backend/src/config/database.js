require('dotenv').config();
require('./databaseUrl')();

// Settings for sequelize-cli; the running app connects through src/models/index.js
const base = {
  use_env_variable: 'DATABASE_URL',
  dialect: 'postgres',
  logging: false,
  migrationStorageTableName: 'sequelize_meta',
  ...(process.env.DB_SSL === 'true' && { dialectOptions: { ssl: { require: true, rejectUnauthorized: false } } }),
};

module.exports = {
  development: base,
  test: base,
  production: base,
};
