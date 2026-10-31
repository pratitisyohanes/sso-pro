const { Op } = require('sequelize');
const { PasswordReset, SsoSession } = require('../../models');
const env = require('../../config/env');
const ldap = require('../../ldap/ldap.gateway');
const ApiError = require('../../utils/ApiError');
const audit = require('../../utils/audit');
const mailer = require('../../utils/mailer');
const { randomToken, sha256 } = require('../../utils/randomToken');
const { hashSsha } = require('../../utils/ssha');
const usersService = require('../users/users.service');

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const LINK_MINUTES = 30;
const MAX_REQUESTS_PER_HOUR = 3;

const INVALID_LINK = 'This reset link is invalid or has expired';

// A failed email must never change what the page answers, so errors only reach the log
const sendInBackground = (work) =>
  work().catch((error) => console.error('Failed to send email:', error.message));

// Logging out everywhere: deleting a session also deletes its refresh tokens (foreign key cascade),
// so every app that logged in through it has to sign in again
const endSessions = (userId, exceptSessionId) =>
  SsoSession.destroy({ where: { userId, ...(exceptSessionId && { id: { [Op.ne]: exceptSessionId } }) } });

// Makes one reset link for an account. Older unused links are marked used (not deleted), so they still count towards the hourly limit.
// Used by the email request below and by the administrator script (npm run user:reset-link)
const createResetLink = async (account, { ip, minutes = LINK_MINUTES } = {}) => {
  await PasswordReset.update({ usedAt: new Date() }, { where: { userId: account.id, usedAt: null } });
  const token = randomToken();
  const expiresAt = new Date(Date.now() + minutes * MINUTE_MS);
  await PasswordReset.create({ userId: account.id, tokenHash: sha256(token), expiresAt, ip });
  return { link: `${env.PUBLIC_URL}/reset?token=${encodeURIComponent(token)}`, expiresAt };
};

// The answer to "I forgot my password" is the same whether or not the email exists (no account guessing),
// and the email is sent after the answer, so the response time does not give it away either
const requestReset = async (email, { ip }) => {
  const account = await ldap.findByEmail(email);
  const log = (result) => audit({ action: 'PASSWORD_RESET_REQUEST', result, username: email, userId: account?.id, ip });

  if (!account || account.disabled) return log(account ? 'DISABLED' : 'UNKNOWN_EMAIL');

  const recent = await PasswordReset.count({ where: { userId: account.id, createdAt: { [Op.gt]: new Date(Date.now() - HOUR_MS) } } });
  if (recent >= MAX_REQUESTS_PER_HOUR) return log('THROTTLED');

  // Only the newest link works
  const { link } = await createResetLink(account, { ip });
  await log('SUCCESS');

  sendInBackground(() => mailer.sendPasswordReset({ to: account.email, name: account.name, link, minutes: LINK_MINUTES }));
  return undefined;
};

// A link works while it is unused and unexpired
const findValidReset = (token) => {
  if (typeof token !== 'string' || token.length < 10 || token.length > 100) return null;
  return PasswordReset.findOne({ where: { tokenHash: sha256(token), usedAt: null, expiresAt: { [Op.gt]: new Date() } } });
};

const resetPassword = async (token, newPassword, { ip }) => {
  const reset = await findValidReset(token);
  if (!reset) throw ApiError.badRequest(INVALID_LINK);

  // Claim the link first: of two requests using it at the same moment, only one gets a row back
  const [claimed] = await PasswordReset.update({ usedAt: new Date() }, { where: { id: reset.id, usedAt: null } });
  if (!claimed) throw ApiError.badRequest(INVALID_LINK);

  const account = await ldap.findById(reset.userId);
  if (!account || account.disabled) throw ApiError.badRequest(INVALID_LINK);

  await ldap.updatePerson(account.id, { passwordHash: hashSsha(newPassword) });
  await endSessions(account.id);
  await audit({ action: 'PASSWORD_RESET', result: 'SUCCESS', username: account.email, userId: account.id, ip });

  sendInBackground(() => mailer.sendPasswordChanged({ to: account.email, name: account.name }));
};

// The current password is checked by users.service (a bind as the user); other devices are logged out afterwards
const changePassword = async (session, { currentPassword, newPassword }, context) => {
  if (currentPassword === newPassword) throw ApiError.badRequest('Choose a password different from the current one');

  await usersService.updateUser(session.userId, { currentPassword, newPassword }, context);
  await endSessions(session.userId, session.id);

  if (env.MAIL_ENABLED) sendInBackground(() => mailer.sendPasswordChanged({ to: session.email, name: session.name }));
};

module.exports = { createResetLink, requestReset, findValidReset, resetPassword, changePassword, endSessions, LINK_MINUTES };
