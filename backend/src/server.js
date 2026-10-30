const app = require('./app');
const env = require('./config/env');
const { sequelize } = require('./models');

// Verify the database connection before accepting requests; LDAP is checked per request and in /health
const start = async () => {
  await sequelize.authenticate();
  const server = app.listen(env.PORT, env.HOST, () => {
    console.log(`auth-service running on http://${env.HOST}:${env.PORT}`);
    console.log(`LDAP directory expected at ${env.LDAP_URL} (${env.LDAP_BASE_DN})`);
  });

  const shutdown = async (signal) => {
    console.log(`${signal} received, shutting down`);
    server.close();
    await sequelize.close();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
};

start().catch(async (err) => {
  console.error('Failed to start server:', err.message);
  await sequelize.close();
  process.exit(1);
});
