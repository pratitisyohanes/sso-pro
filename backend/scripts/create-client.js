// Register or rotate an application allowed to call auth-service
// Usage: npm run client:create -- booking-api "Booking API" "auth:validate users:read users:write"
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { sequelize, Client } = require('../src/models');

const KNOWN_SCOPES = ['auth:validate', 'users:read', 'users:write', 'users:admin'];

const run = async () => {
  const [id, name, scopeList = 'auth:validate'] = process.argv.slice(2);
  if (!id || !name) {
    console.error('Usage: npm run client:create -- <client-id> "<name>" "<scope scope ...>"');
    process.exit(1);
  }

  const scopes = scopeList.split(' ').filter(Boolean);
  const unknown = scopes.filter((scope) => !KNOWN_SCOPES.includes(scope));
  if (unknown.length) {
    console.error(`Unknown scope: ${unknown.join(', ')}. Allowed: ${KNOWN_SCOPES.join(', ')}`);
    process.exit(1);
  }

  // Shown once; only the bcrypt hash is stored, like a password
  const secret = crypto.randomBytes(32).toString('base64url');
  const secretHash = await bcrypt.hash(secret, 10);
  await Client.upsert({ id, name, scopes, secretHash, isActive: true });

  console.log(`Client "${id}" saved with scopes: ${scopes.join(' ')}`);
  console.log('Put these in the calling service .env (the secret is not shown again):');
  console.log(`AUTH_CLIENT_ID=${id}`);
  console.log(`AUTH_CLIENT_SECRET=${secret}`);
};

run()
  .catch((error) => {
    console.error('Failed to save client:', error.message);
    process.exitCode = 1;
  })
  .finally(() => sequelize.close());
