// Create the RS256 signing key once per environment: npm run keys:generate
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const target = path.resolve(process.env.JWT_PRIVATE_KEY_PATH || './keys/private.pem');

if (fs.existsSync(target)) {
  console.log(`Key already exists at ${target}; delete it first if you really want a new one.`);
  process.exit(0);
}

const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
fs.mkdirSync(path.dirname(target), { recursive: true });
// 0o600: readable only by the user that runs PM2 (ignored on Windows)
fs.writeFileSync(target, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
console.log(`Private key written to ${target}. Never commit it.`);
