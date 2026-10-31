const { Sequelize, DataTypes } = require('sequelize');
const env = require('../config/env');

// Single shared database connection; user accounts live in LDAP, not here
const sequelize = new Sequelize(env.DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectOptions: env.DB_SSL ? { ssl: { require: true, rejectUnauthorized: false } } : {},
});

const models = {
  Client: require('./client')(sequelize, DataTypes),
  AuthEvent: require('./authEvent')(sequelize, DataTypes),
  // Stage 2: single sign-on
  SsoSession: require('./ssoSession')(sequelize, DataTypes),
  AuthorizationCode: require('./authorizationCode')(sequelize, DataTypes),
  RefreshToken: require('./refreshToken')(sequelize, DataTypes),
  MfaFactor: require('./mfaFactor')(sequelize, DataTypes),
  PasswordReset: require('./passwordReset')(sequelize, DataTypes),
};

Object.values(models).forEach((model) => model.associate?.(models));

module.exports = { sequelize, Sequelize, ...models };
