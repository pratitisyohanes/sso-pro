const crypto = require('crypto');

// {SSHA} is the salted SHA-1 format slapd understands natively: base64(sha1(password + salt) + salt)
const hashSsha = (password, salt = crypto.randomBytes(8)) => {
  const digest = crypto.createHash('sha1').update(password).update(salt).digest();
  return `{SSHA}${Buffer.concat([digest, salt]).toString('base64')}`;
};

// Used by tests; real password checks always happen through an LDAP bind
const verifySsha = (password, hashed) => {
  if (!hashed.startsWith('{SSHA}')) return false;
  const raw = Buffer.from(hashed.slice(6), 'base64');
  return hashSsha(password, raw.subarray(20)) === hashed;
};

module.exports = { hashSsha, verifySsha };
