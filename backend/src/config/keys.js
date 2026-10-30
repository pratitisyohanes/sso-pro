const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exportJWK } = require('jose');
const env = require('./env');

const keyPath = path.resolve(env.JWT_PRIVATE_KEY_PATH);

if (!fs.existsSync(keyPath)) {
  console.error(`Private key not found at ${keyPath}. Run: npm run keys:generate`);
  process.exit(1);
}

// Only auth-service holds the private key; the public key is derived from it for verification
const privateKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
const publicKey = crypto.createPublicKey(privateKey);

// Published at /.well-known/jwks.json so booking-api and pos-api can verify user tokens without any secret
let jwksCache;
const getJwks = async () => {
  if (!jwksCache) {
    jwksCache = { keys: [{ ...(await exportJWK(publicKey)), kid: env.JWT_KEY_ID, alg: 'RS256', use: 'sig' }] };
  }
  return jwksCache;
};

module.exports = { privateKey, publicKey, getJwks };
