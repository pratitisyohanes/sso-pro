// Print an {SSHA} hash for an LDIF file, for machines without slappasswd
// Usage: npm run ldap:hash -- "User12345"
const { hashSsha } = require('../src/utils/ssha');

const password = process.argv[2];
if (!password) {
  console.error('Usage: npm run ldap:hash -- "<password>"');
  process.exit(1);
}

console.log(hashSsha(password));
