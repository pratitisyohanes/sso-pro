const crypto = require('crypto');
const env = require('../config/env');
const ApiError = require('./ApiError');

const ALGORITHM = 'aes-256-gcm';

const getKey = () => {
  if (!env.MFA_ENCRYPTION_KEY) throw new ApiError(503, 'Two-factor authentication is not configured on this server');
  return Buffer.from(env.MFA_ENCRYPTION_KEY, 'hex');
};

// Stored as iv.tag.ciphertext (base64url); GCM also detects any change to the stored value
const encrypt = (plainText) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64url')).join('.');
};

const decrypt = (stored) => {
  const [iv, tag, encrypted] = stored.split('.').map((part) => Buffer.from(part, 'base64url'));
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
};

module.exports = { encrypt, decrypt };
