const { SsoSession } = require('../../models');
const env = require('../../config/env');
const ldap = require('../../ldap/ldap.gateway');
const ApiError = require('../../utils/ApiError');
const audit = require('../../utils/audit');
const { randomToken, sha256 } = require('../../utils/randomToken');
const usersService = require('../users/users.service');
const mfaService = require('./mfa.service');

const HOUR_MS = 60 * 60 * 1000;
const PENDING_MS = 5 * 60 * 1000;
const MAX_CODE_ATTEMPTS = 5;

const sessionMs = () => env.SESSION_HOURS * HOUR_MS;

// The cookie gets the random sid; the table keeps only its hash, like refresh tokens
const createSession = async (account, stage, { ip, userAgent }) => {
  const sid = randomToken();
  const maxAge = stage === 'ACTIVE' ? sessionMs() : PENDING_MS;
  await SsoSession.create({
    sidHash: sha256(sid),
    userId: account.id,
    name: account.name,
    email: account.email,
    role: account.role,
    stage,
    userAgent: userAgent?.slice(0, 255),
    ip,
    expiresAt: new Date(Date.now() + maxAge),
    lastSeenAt: new Date(),
  });
  return { sid, stage, maxAge };
};

// Second factor: required when the user turned it on, or for every admin when MFA_ENFORCE_ADMIN=true
const stageFor = async (account) => {
  const factor = await mfaService.findFactor(account.id);
  if (factor?.enabled) return 'MFA_VERIFY';
  if (account.role === 'ADMIN' && env.MFA_ENFORCE_ADMIN) return 'MFA_SETUP';
  return 'ACTIVE';
};

// Password step on the KandangID page: the same search-then-bind as /api/v1/auth/validate
const passwordLogin = async ({ email, password }, context) => {
  const account = await ldap.verifyCredentials(email, password);
  let result = 'SUCCESS';
  if (!account) result = 'INVALID_CREDENTIALS';
  else if (account.disabled) result = 'DISABLED';
  await audit({ client: context.client, action: 'LOGIN', result, username: email, userId: account?.id, ip: context.ip });

  if (!account) throw ApiError.unauthorized('Invalid email or password');
  if (account.disabled) throw ApiError.forbidden('This account has been deactivated. Contact the administrator.');

  return createSession(account, await stageFor(account), context);
};

// Each wrong code counts; after five the half-finished session is thrown away and the user starts again
const verifySecondFactor = async (session, code, context) => {
  const isValid = await mfaService.checkCode(session, code);
  await audit({ client: context.client, action: session.stage === 'MFA_SETUP' ? 'MFA_SETUP' : 'MFA_VERIFY', result: isValid ? 'SUCCESS' : 'INVALID_CODE', username: session.email, userId: session.userId, ip: context.ip });

  if (!isValid) {
    const attempts = session.mfaAttempts + 1;
    if (attempts >= MAX_CODE_ATTEMPTS) {
      await session.destroy();
      throw new ApiError(429, 'Too many wrong codes. Log in again.');
    }
    await session.update({ mfaAttempts: attempts });
    throw ApiError.badRequest('Invalid verification code');
  }

  await session.update({ stage: 'ACTIVE', mfaAttempts: 0, expiresAt: new Date(Date.now() + sessionMs()) });
  return { maxAge: sessionMs() };
};

// Register creates the LDAP entry (always in cn=customers) and logs the new user in straight away
const register = async (data, context) => {
  const account = await usersService.createUser({ name: data.name, email: data.email, phone: data.phone, password: data.password }, { client: context.client, ip: context.ip });
  return createSession(account, 'ACTIVE', context);
};

module.exports = { passwordLogin, verifySecondFactor, register, PENDING_MS };
