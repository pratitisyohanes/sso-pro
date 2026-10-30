// Register a browser app (public OIDC client, no secret) with its origins
// Usage: npm run client:web -- booking-web "Booking" "http://localhost:5173,https://booking.pratitis.net"
const { sequelize, Client } = require('../src/models');

const CALLBACK_PATH = '/login/callback';

const run = async () => {
  const [id, name, originList] = process.argv.slice(2);
  if (!id || !name || !originList) {
    console.error('Usage: npm run client:web -- <client-id> "<name>" "<origin,origin,...>"');
    process.exit(1);
  }

  const origins = originList.split(',').map((origin) => origin.trim().replace(/\/+$/, '')).filter(Boolean);
  const invalid = origins.filter((origin) => !/^https?:\/\/[^/]+$/.test(origin));
  if (invalid.length) {
    console.error(`Not an origin (scheme://host[:port], no path): ${invalid.join(', ')}`);
    process.exit(1);
  }

  // Exact addresses only; /oidc/authorize refuses anything not listed here
  const redirectUris = origins.map((origin) => `${origin}${CALLBACK_PATH}`);
  const postLogoutRedirectUris = origins.map((origin) => `${origin}/`);

  await Client.upsert({ id, name, secretHash: null, scopes: [], redirectUris, postLogoutRedirectUris, allowedOrigins: origins, isActive: true });

  console.log(`Web client "${id}" saved.`);
  console.log(`  redirect_uris: ${redirectUris.join(' ')}`);
  console.log(`  post_logout:   ${postLogoutRedirectUris.join(' ')}`);
  console.log('Put this in the frontend .env:');
  console.log(`VITE_SSO_CLIENT_ID=${id}`);
};

run()
  .catch((error) => {
    console.error('Failed to save client:', error.message);
    process.exitCode = 1;
  })
  .finally(() => sequelize.close());
