// Test environment values; LDAP and the database are mocked in every test
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const keyPath = path.join(os.tmpdir(), 'sso-pro-test-private.pem');
if (!fs.existsSync(keyPath)) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
}

process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://test:test@localhost:5432/test_db';
process.env.LDAP_URL = 'ldap://127.0.0.1:3899';
process.env.LDAP_BIND_DN = 'cn=auth-service,ou=services,dc=kandang,dc=local';
process.env.LDAP_BIND_PASSWORD = 'test-service-secret';
process.env.JWT_PRIVATE_KEY_PATH = keyPath;
